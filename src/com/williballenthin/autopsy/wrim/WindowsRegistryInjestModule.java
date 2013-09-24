/*
 * Autopsy Forensic Browser
 *
 * Copyright 2013 Willi Ballenthin
 * Contact: willi.ballenthin@gmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.williballenthin.autopsy.wrim;

import com.williballenthin.rejistry.Cell;
import com.williballenthin.rejistry.HBIN;
import com.williballenthin.rejistry.REGFHeader;
import com.williballenthin.rejistry.RegistryHive;
import com.williballenthin.rejistry.RegistryHiveBuffer;
import com.williballenthin.rejistry.RegistryKey;
import com.williballenthin.rejistry.RegistryParseException;
import com.williballenthin.rejistry.RegistryValue;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.logging.Level;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.ingest.IngestModuleAbstractFile;
import org.sleuthkit.autopsy.ingest.IngestModuleInit;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.datamodel.AbstractFile;
import org.netbeans.api.progress.ProgressHandle;
import org.netbeans.api.progress.ProgressHandleFactory;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.ingest.PipelineContext;
import org.sleuthkit.autopsy.ingest.IngestMessage;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskException;

/**
 * Windows Registry ingest module extracts keys and values, adds them
 *   as DerivedFiles, and reschedules them for ingest.
 *
 * Updates datamodel / directory tree with new files.
 */
public final class WindowsRegistryInjestModule extends IngestModuleAbstractFile {
    
    
    /**
     *  Implementation notes:
     * 
     *  Until this notice is removed, this code is a bit of a mess.  It works,
     *    but don't assume that if something looks funky, I'm trying to do 
     *    something clever. Rather, I'm probably doing it wrong.
     * 
     *  So, here's whats happens:
     *    - we look for files with a Registry hive header
     *    - then we extract each key or value to a directory or file, respectively
     *        in the module output directory
     *    - then we add this content as a derived file in the data model
     * 
     *  Some things that need work:
     *    - the progress bar does not seem to be working correctly (shows 100%)
     * 
     *  Some things that would be nice from the Autopsy devs:
     *    - "rederivation" of the hive  artifacts instead of extracting them
     *        to the file system. Extraction seems like a bit of a waste?
     *    - Plugins that can add services to a service manager, so we can 
     *        request the RegistryService or something rather than BYOL (bring
     *        your own library)
     */
    
    
    // Let's start with some relevant constants
    private static final int ONE_HUNDRED_MEGABYTES = 1024 * 1024 * 100;
    private static final int MAX_HIVE_SIZE = ONE_HUNDRED_MEGABYTES;
    private static final int ONE_GIGABYTE = 1024 * 1024 * 1024;
    private static final String EXTRACTED_VALUE_EXTENSION = ".bin";
    public static final String MODULE_NAME = "Windows Registry Extractor";
    public static final String MODULE_DESCRIPTION = "Extracts Windows Registry hives, reschedules them to current ingest and populates directory tree with keys and values.";
    public static final String MODULE_VERSION = "1.0";
    
    
    private static final Logger logger = Logger.getLogger(WindowsRegistryInjestModule.class.getName());    
    
    private IngestServices services;  ///< services is the manager for interacting with the rest of Autopsy.
    private volatile int messageID = 0;  ///< messageID is used to ensure error messages are unique when posted.
    private boolean initialized = false;  ///< initialized is set once the singleton has been constructed.
    private static WindowsRegistryInjestModule instance = null;  ///< instance is the singleton instance.
    private String unpackDirAbsPath; ///< unpackDirAbsPath is the absolute path to a case and module specific directory for unpacking Registry hive data.
    private FileManager fileManager; ///< fileManager organizes access to case files.
   
    /**
     * Private constructor ensures singleton instance.
     */
    private WindowsRegistryInjestModule() {  }

    /**
     * Returns singleton instance of the module, creates one if needed.
     *
     * @return instance of this class.
     */
    public static synchronized WindowsRegistryInjestModule getDefault() {
        if (instance == null) {
            instance = new WindowsRegistryInjestModule();
        }
        return instance;
    }

    @Override
    public void init(IngestModuleInit initContext) {
        logger.log(Level.INFO, "init()");
        services = IngestServices.getDefault();
        initialized = false;

        final Case currentCase = Case.getCurrentCase();
        unpackDirAbsPath = currentCase.getModulesOutputDirAbsPath() + File.separator + MODULE_NAME;
        fileManager = currentCase.getServices().getFileManager();

        File unpackDirPathFile = new File(unpackDirAbsPath);
        if (!unpackDirPathFile.exists()) {
            try {
                logger.log(Level.INFO, "Creating module output directory: {0}", unpackDirAbsPath);
                unpackDirPathFile.mkdirs();
            } catch (SecurityException e) {
                logger.log(Level.SEVERE, "Error initializing output dir: " + unpackDirAbsPath, e);
                String msg = "Error initializing " + MODULE_NAME;
                String details = "Error initializing output dir: " + unpackDirAbsPath + ": " + e.getMessage();
                services.postMessage(IngestMessage.createErrorMessage(++messageID, instance, msg, details));
                return;
            }
        }
        initialized = true;
    }

    /**
     * isSupported returns True if we'd like to process the file -- that is, if
     *   it appears to be a Registry hive.
     * 
     * @param hiveFile A file to test.
     * @return True if we'd like to process the file, False otherwise.
     */
    private boolean isSupported(AbstractFile abstractFile) {
        logger.log(Level.INFO, "isSupported: {0}", this);
        if (abstractFile == null) {
            return false;
        }
        
        if (abstractFile.isFile() == false) {
            return false;
        }
        
        if (abstractFile.getSize() == 0 || abstractFile.getSize() > MAX_HIVE_SIZE) {
            return false;
        }
        
        byte[] header = new byte[REGFHeader.FIRST_HBIN_OFFSET];
        
        int bytesRead = 0;
        try {
            int bytesToRead = (int) Math.min(REGFHeader.FIRST_HBIN_OFFSET, abstractFile.getSize());
            // TODO(wb): Lazy to assume read gets all the bytes!            
            bytesRead += abstractFile.read(header, 0x0, bytesToRead);
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, "Failed to read file content.", ex);
            return false;
        }
        
        ByteBuffer buf = ByteBuffer.wrap(header);
        RegistryHive hive = new RegistryHiveBuffer(buf);
        try {
            REGFHeader h = hive.getHeader();
            return true;
        } catch (RegistryParseException ex) {
            return false;
        }
    }

    /**
     * Given the derived path to a resource to unpack, return the absolute path to the 
     *   absolute path to which it should be extracted to in the case and module
     *   specific directory.
     * 
     * @param derivedPath The derived path to a resource to unpack (such as "NTUSER.DAT_5/$$$PROTO.HIV/7-zip").
     * @return An absolute path that the resource should be extracted to.
     */
    private String getExtractionDirectoryPathForFile(String derivedPath) {
        return unpackDirAbsPath + File.separator + derivedPath;
    }    
    
    /**
     * Given the derived path to a file, return the path relative to the case
     *   directory that it would be extracted to.
     * 
     * HACK: This hardcodes the path prefix "ModuleOutput" based on empirical testing.
     * 
     * @param derivedPath The derived path to a resource to unpack (such as "NTUSER.DAT_5/$$$PROTO.HIV/7-zip").
     * @return The case relative path that the resource would extract to.
     */
    private String getCaseRelativeExtractionDirectoryPathForFile(String derivedPath) {
        return "ModuleOutput" + File.separator + MODULE_NAME + File.separator + derivedPath;
    }
    
    /**
     * countCells counts the total number of cells in a Registry hive. This 
     *  includes both the active and inactive cells. If an error is encountered,
     *  return the number of cells encountered so far.
     * 
     * @param hive The RegistryHive to process.
     * @return The total number of cells in the Registry hive.
     */
    private int countCells(RegistryHive hive) {
        int numItems = 0;
        try {
            Iterator<HBIN> hit = hive.getHeader().getHBINs();
            while (hit.hasNext()) {
                HBIN hbin = hit.next();
                
                Iterator<Cell> cit = hbin.getCells();
                while (cit.hasNext()) {
                    Cell c = cit.next();
                    if (c.isActive()) {
                        numItems++;
                    }
                }
            }
        } catch (RegistryParseException ex) {
            return numItems;
        }
        return numItems;
    }
    
    /**
     * An exception to throw when a key extracts to the same path that a value
     *   does.
     */
    private class PathAlreadyExistsException extends Exception {
        public PathAlreadyExistsException() {};
    }    
    
        
    private String sanitizePathComponent(String s) throws UnsupportedEncodingException {
        if ( ! s.matches("[a-zA-Z0-9\\.\\*\\-_]")) {
            return URLEncoder.encode(s, "UTF-8");
        }
        return s;
    }
    
    @Override
    public ProcessResult process(PipelineContext<IngestModuleAbstractFile> pipelineContext_, AbstractFile abstractFile_) {
        final PipelineContext<IngestModuleAbstractFile> pipelineContext = pipelineContext_;
        final AbstractFile hiveFile = abstractFile_;

        if (initialized == false) { //error initializing the module
            logger.log(Level.WARNING, "Skipping processing, module not initialized, file: {0}", hiveFile.getName());
            return ProcessResult.OK;
        }

        if ( ! isSupported(hiveFile)) {
            return ProcessResult.OK;
        }

        /**
         * hive_filename is a unique name suitable to exist in the root of the 
         *   module output directory.
         */    
        final String hive_filename = hiveFile.getName() + "_" + hiveFile.getId();
        
        /**
         * hive_extraction_directory is the absolute path of the hive_filename
         *   in the case and module specific output directory.
         */
        final String hive_extraction_directory = getExtractionDirectoryPathForFile(hive_filename);
        
        if ((new File(hive_extraction_directory)).exists()) {
            logger.log(Level.INFO, "Hive already has been processed as it has children and local unpacked file, skipping: {0}", hiveFile.getName());
            return ProcessResult.OK;
        }

        final int hiveSize = (int)hiveFile.getSize();
        final byte[] data = new byte[hiveSize];
        int bytesRead = 0;        
        try {
            // TODO(wb): Lazy to assume read returns all the requested bytes!            
            bytesRead += hiveFile.read(data, 0x0, hiveSize);
        } catch (TskException ex) {
            logger.log(Level.WARNING, "Failed to read hive content.", ex);
            // continue and parse out as much as we can
        }
        
        final ByteBuffer buf = ByteBuffer.wrap(data);
        final RegistryHive hive = new RegistryHiveBuffer(buf);
        final ProgressHandle progress = ProgressHandleFactory.createHandle(MODULE_NAME);
        final Counter processedItems = new Counter();
        final NewDerivedFileHandler handler = new NewDerivedFileHandler(MODULE_NAME, progress, processedItems, pipelineContext, fileManager, services, hiveFile);
        final Deque<QueuedKey> queuedKeys = new LinkedList<QueuedKey>();
        final RegistryKey root;
        
        // This is a depth-first traversal of the Registry that extracts
        //  each key to a derived directory and each value to a derived file.
        //  Each of these items is added to TSK and re-processed as its own file.
        //  For each key:
        //    1. create the directory in the extraction directory and queue for Autopsy
        //    2. extract each value and queue for Autopsy
        //    3. queue up each subkey

        try {
            root = hive.getRoot();
            queuedKeys.add(new QueuedKey(hiveFile, "", hive_filename, root));            
        } catch (RegistryParseException ex) {
            logger.log(Level.WARNING, "Error parsing registry hive (can't get the root key)");
            // don't need to leave here, cause we know the queue is empty
        }

        progress.start(countCells(hive));
        while (queuedKeys.size() > 0) {
            final QueuedKey currentKey = queuedKeys.remove();
            
            final String name;
            final String sanitizedName;
            final String keyRegistryPath;
            final String keyFileSystemPath;
            final AbstractFile currentKeyFile;
            try {
                name = currentKey.key.getName();
                sanitizedName = sanitizePathComponent(name);
            } catch (UnsupportedEncodingException ex) {
                logger.log(Level.WARNING, "Error parsing registry hive (encoding)");
                continue;
            }
            keyRegistryPath = currentKey.parentRegistryPath + "\\" + name;
            keyFileSystemPath = currentKey.parentFileSystemPath + File.separator + sanitizedName;
            
            // drop this directory            
            try {
                dropLocalDirectory(getExtractionDirectoryPathForFile(keyFileSystemPath));
            } catch (PathAlreadyExistsException ex) {
                continue;
            }
            
            // add self
            try {
                currentKeyFile = handler.addNewKey(currentKey.key, currentKey.parentFile, name, getCaseRelativeExtractionDirectoryPathForFile(keyFileSystemPath));
            } catch (FailedToAddDerivedFileException ex) {
                continue;
            }
                
            // drop each value
            try {     
                for (RegistryValue value : currentKey.key.getValueList()) {
                    String valueName;
                    final String valueSanitizedName;
                    final String valueFileSystemPath;
                    final ByteBuffer valueData;                    

                    try {
                        valueName = value.getName();
                        if ("".equals(valueName)) {
                            valueName = "(default)";
                        }
                        valueSanitizedName = sanitizePathComponent(valueName);
                        valueData = value.getValue().getAsRawData();                    
                    } catch (UnsupportedEncodingException ex) {
                        logger.log(Level.WARNING, "Error parsing registry hive (encoding)");
                        continue;
                    } catch (RegistryParseException ex) {
                        logger.log(Level.WARNING, "Error parsing registry hive (parse)");
                        continue;
                    }
                    valueFileSystemPath = keyFileSystemPath + File.separator + valueSanitizedName + EXTRACTED_VALUE_EXTENSION;
                    valueData.position(0x0);  
                    
                    try {
                        dropLocalFile(getExtractionDirectoryPathForFile(valueFileSystemPath), valueData);
                    } catch (PathAlreadyExistsException ex) {
                        continue;
                    }
                    
                    try {
                        handler.addNewValue(value, currentKeyFile, valueName, getCaseRelativeExtractionDirectoryPathForFile(valueFileSystemPath));
                    } catch (FailedToAddDerivedFileException ex) {
                        continue;
                    }
                }
            } catch (RegistryParseException ex) {
                logger.log(Level.WARNING, "Error parsing registry hive");
                // yes, ignoring this, need to queue up the subkeys
            }
            
            // add each key to the queue         
            try {
                for (RegistryKey subkey : currentKey.key.getSubkeyList()) {
                    queuedKeys.add(new QueuedKey(currentKeyFile, keyRegistryPath, keyFileSystemPath, subkey));
                }
            } catch (RegistryParseException ex) {
                logger.log(Level.WARNING, "Error parsing registry hive");
                // yes, ignoring this, need to finish the queue
            }
        }
        handler.commit();

        progress.finish();
        return ProcessResult.OK;
    }
    
    /**
     * dropLocalFile extracts the given content to the provided derived path.
     * 
     * More or less ignores errors because there's not much we can do to recover
     *   during this context (ingest).
     * 
     * @param path The path of the content to extract.
     * @param content The binary data that will be written to the file system.
     * @throws com.williballenthin.autopsy.wrim.WindowsRegistryInjestModule.PathAlreadyExistsException If the path already exists for a *key* with the same name.
     */
    private void dropLocalFile(String path, ByteBuffer content) throws PathAlreadyExistsException {
        File localFile = new java.io.File(path);

        if (localFile.exists() && localFile.isDirectory()) {
            throw new PathAlreadyExistsException();
        }
        
        if (localFile.exists()) {
            return;
        }
        
        try {
            localFile.getParentFile().mkdirs();
            localFile.createNewFile();
        } catch (SecurityException e) {
            logger.log(Level.SEVERE, "Error setting up output path for unpacked file: " + localFile.getAbsolutePath(), e);
            return;
        } catch (IOException ex) {
            logger.log(Level.SEVERE, "Error creating extracted file: " + localFile.getAbsolutePath(), ex);
            return;
        }
        
        try {
            FileChannel chan = new FileOutputStream(localFile, false).getChannel();
            content.position(0x0);
            chan.write(content);
            chan.close();
        } catch (FileNotFoundException ex) {
            logger.log(Level.SEVERE, "Error writing derived file contents: " + localFile.getAbsolutePath(), ex);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, "Error writing derived file contents: " + localFile.getAbsolutePath(), ex);
        }
    }
    
    /**
     * dropLocalDirectory extracts the given content to the provided derived path.
     * 
     * More or less ignores errors because there's not much we can do to recover
     *   during this context (ingest).
     * 
     * @param path The directory path to extract (create).
     * @throws com.williballenthin.autopsy.wrim.WindowsRegistryInjestModule.PathAlreadyExistsException If the path already exists for a *value* with the same name.
     */    
    private void dropLocalDirectory(String path) throws PathAlreadyExistsException {
        File localFile = new java.io.File(path);
        
        if (localFile.exists() && ! localFile.isDirectory()) {
            throw new PathAlreadyExistsException();
        }

        if (localFile.exists()) {
            return;
        }
        
        try {
            localFile.mkdirs();
        } catch (SecurityException e) {
            logger.log(Level.SEVERE, "Error setting up output path for unpacked file: " + localFile.getAbsolutePath(), e);
        }
    }
    
    @Override
    public void complete() {
        logger.log(Level.INFO, "complete()");
        if (initialized == false) {
            return;
        }
    }

    @Override
    public void stop() {
        logger.log(Level.INFO, "stop()");
    }

    @Override
    public String getName() {
        return MODULE_NAME;
    }

    @Override
    public String getDescription() {
        return MODULE_DESCRIPTION;
    }

    @Override
    public String getVersion() {
        return MODULE_VERSION;
    }

    @Override
    public boolean hasBackgroundJobsRunning() {
        return false;
    }
}
