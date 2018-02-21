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
import java.util.regex.Pattern;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.datamodel.AbstractFile;
import org.netbeans.api.progress.ProgressHandle;
import org.netbeans.api.progress.ProgressHandleFactory;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestMessage;
import org.sleuthkit.autopsy.ingest.IngestModuleReferenceCounter;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskException;

/**
 * Windows Registry ingest module extracts keys and values, adds them
 *   as DerivedFiles, and reschedules them for ingest.
 *
 * Updates datamodel / directory tree with new files.
 */
public final class WindowsRegistryInjestModule implements FileIngestModule {
    
    
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
    
    
    private static final Logger logger = Logger.getLogger(WindowsRegistryInjestModule.class.getName());    
    
    private IngestServices services;  ///< services is the manager for interacting with the rest of Autopsy.
    private boolean initialized = false;  ///< initialized is set once the singleton has been constructed.
    private static WindowsRegistryInjestModule instance = null;  ///< instance is the singleton instance.
    private String unpackDirAbsPath; ///< unpackDirAbsPath is the absolute path to a case and module specific directory for unpacking Registry hive data.
    private FileManager fileManager; ///< fileManager organizes access to case files.
    private IngestJobContext context;
    private final static IngestModuleReferenceCounter refCounter = new IngestModuleReferenceCounter();
    private long jobId;
   

    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        logger.log(Level.INFO, "init()");
        services = IngestServices.getInstance();
        this.context = context;
        jobId = context.getJobId();

        if (refCounter.incrementAndGet(jobId) == 1) {
            final Case currentCase = Case.getCurrentCase();
            unpackDirAbsPath = currentCase.getModulesOutputDirAbsPath() + File.separator + WindowsRegistryModuleFactory.getModuleName();
            fileManager = currentCase.getServices().getFileManager();

            File unpackDirPathFile = new File(unpackDirAbsPath);
            if (!unpackDirPathFile.exists()) {
                try {
                    logger.log(Level.INFO, "Creating module output directory: {0}", unpackDirAbsPath);
                    unpackDirPathFile.mkdirs();
                } catch (SecurityException e) {
                    logger.log(Level.SEVERE, "Error initializing output dir: " + unpackDirAbsPath, e);
                    String msg = "Error initializing " + WindowsRegistryModuleFactory.getModuleName();
                    String details = "Error initializing output dir: " + unpackDirAbsPath + ": " + e.getMessage();
                    services.postMessage(IngestMessage.createErrorMessage(WindowsRegistryModuleFactory.getModuleName(), msg, details));
                }
            }
        }
    }

    /**
     * isSupported returns True if we'd like to process the file -- that is, if
     *   it appears to be a Registry hive.
     * 
     * @param hiveFile A file to test.
     * @return True if we'd like to process the file, False otherwise.
     */
    private boolean isSupported(AbstractFile abstractFile) {
        //logger.log(Level.INFO, "isSupported: {0}", this);
        if (abstractFile == null) {
            return false;
        }
        
        if (abstractFile.isFile() == false) {
            return false;
        }
 
//   Put this in to do all registry files.
        if (abstractFile.getSize() == 0) {
      
//        if (abstractFile.getSize() == 0 || abstractFile.getSize() > MAX_HIVE_SIZE) {
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
            final Case currentCase = Case.getCurrentCase();
            unpackDirAbsPath = currentCase.getModulesOutputDirAbsPath() + File.separator + WindowsRegistryModuleFactory.getModuleName();
            fileManager = currentCase.getServices().getFileManager();        
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
        return "ModuleOutput" + File.separator + WindowsRegistryModuleFactory.getModuleName() + File.separator + derivedPath;
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


    @Override
    public void shutDown() {
        if (refCounter.decrementAndGet(jobId) == 0) {
            logger.log(Level.INFO, "complete()");
        }
    }
    /**
     * An exception to throw when a key extracts to the same path that a value
     *   does.
     */
    private class PathAlreadyExistsException extends Exception {
        public PathAlreadyExistsException() {};
    }    
    
        
    private String sanitizePathComponent(String s) throws UnsupportedEncodingException {
        String newStr = s.replaceAll("\\*+", "_");

        /* According to MSDN article you cannot have a file named these:
        CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, 
        COM9, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, and LPT9
        */
        String newStr1 = newStr.replaceAll("aux", "aux_");
        String newStr2 = newStr1.replaceAll("AUX", "AUX_");
        String newStr3 = newStr2.replaceAll("PRN", "PRN_");
        String newStr4 = newStr3.replaceAll("COM3", "COM3_");
        String newStr5 = newStr4.replaceAll("CON", "CON_");
        if ( ! newStr5.matches("[a-zA-Z0-9\\.\\-_]")) {
            return URLEncoder.encode(newStr5, "UTF-8");
        }
        return newStr5;
    }
    
    @Override
    public ProcessResult process(AbstractFile abstractFile_) {
        final AbstractFile hiveFile = abstractFile_;

        if (refCounter.get(jobId) == 0) { //error initializing the module
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
            logger.log(Level.INFO, "Hive already has been processed as it has children and local unpacked file, skipping: {0}", hive_filename);
            logger.log(Level.INFO, "hive_extraction_directory ==> {0}", hive_extraction_directory);
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
        final ProgressHandle progress = ProgressHandleFactory.createHandle(WindowsRegistryModuleFactory.getModuleName());
        final Counter processedItems = new Counter();
        final NewDerivedFileHandler handler = new NewDerivedFileHandler(WindowsRegistryModuleFactory.getModuleName(), progress, processedItems, context, fileManager, services, hiveFile);
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
            logger.log(Level.WARNING, "Error parsing registry hive (can't get the root key): {0}", hive_filename);
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
                    } catch (Exception e) {
                        logger.log(Level.WARNING, "Error parsing registry hive unknown registry value type");
                        //logger.log(Level.WARNING, "Error in valueName ==> {0}" + value.getName());   
                        //logger.log(Level.WARNING, "Error Valuepath ==> {0}" + valueFileSystemPath);
                        logger.log(Level.WARNING, "Exception is ==> {0}", e);
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
            if (localFile.getAbsolutePath().contains("D:\\Autopsy_Cases\\Registry_Test_m1\\ModuleOutput\\Windows Registry Module\\SYSTEM_58\\ROOT\\ControlSet001\\Control\\Class\\%7B4d36e96c-e325-11ce-bfc1-08002be10318%7D\\0000\\Drivers\\aux\\wdmaud.drv\\Driver.bin")) {
                    
                logger.log(Level.SEVERE, "XXXXXX");
                        
            }
            localFile.getParentFile().mkdirs();
            localFile.createNewFile();
        } catch (SecurityException e) {
            logger.log(Level.SEVERE, "Error setting up output path for unpacked file: " + localFile.getAbsolutePath(), e);
            return;
        } catch (IOException ex) {
            logger.log(Level.SEVERE, "Error creating extracted file: " + localFile.getAbsolutePath() + " IoException is ==> " + ex.getMessage(), ex);
            return;
        }
        
        try {
            if (localFile.getAbsolutePath().contains("D:\\Autopsy_Cases\\Registry_Test_m1\\ModuleOutput\\Windows Registry Module\\SYSTEM_58\\ROOT\\ControlSet001\\Control\\Session+Manager\\DOS+Devices\\AUX.bin")) {
                    
                logger.log(Level.SEVERE, "XXXXXX");
                        
            }
            FileChannel chan = new FileOutputStream(localFile, false).getChannel();
            content.position(0x0);
            chan.write(content);
            chan.close();
        } catch (FileNotFoundException ex) {
            logger.log(Level.SEVERE, "Error writing derived file contents File Not Found: " + localFile.getAbsolutePath(), ex);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, "Error writing derived file contents IO Exception: " + localFile.getAbsolutePath(), ex);
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
}
