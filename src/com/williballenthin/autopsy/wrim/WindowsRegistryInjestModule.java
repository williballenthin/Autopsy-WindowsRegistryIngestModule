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
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
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
import org.sleuthkit.autopsy.ingest.ModuleContentEvent;
import org.sleuthkit.datamodel.DerivedFile;
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
     *    - we post a ScheduleNewFileEvent (or whatever its called) on each new
     *        key/value. Probably should only do this every once in a while.
     *    - the code that handles each key/value is a mess. Perhaps shouldn't 
     *        use recursion here.
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
    public static final String MODULE_NAME = "Windows Registry Extractor";
    public static final String MODULE_DESCRIPTION = "Extracts Windows Registry hives, reschedules them to current ingest and populates directory tree with keys and values.";
    final public static String MODULE_VERSION = "1.0";
    
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
     * @param abstractFile A file to test.
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
     * Counter is a silly class to get around `final` references to variables.
     *   Since we use anonymous classes above to process the keys/values, yet
     *   we want to track the number processed, we use this abomination.
     * 
     *  Somebody tell me a better way to do this.
     */
    private class Counter {
        private int c;
        public Counter() {
            c = 0;
        }

        public void increment() {
            c++;
        }

        public int getValue() {
            return c;
        }
    }
    
    /**
     * An exception to throw when a key extracts to the same path that a value
     *   does.
     */
    private class PathAlreadyExistsException extends Exception {
        public PathAlreadyExistsException() {};
    }    
    
    @Override
    public ProcessResult process(PipelineContext<IngestModuleAbstractFile> pipelineContext_, AbstractFile abstractFile_) {
        final PipelineContext<IngestModuleAbstractFile> pipelineContext = pipelineContext_;
        final AbstractFile abstractFile = abstractFile_;

        if (initialized == false) { //error initializing the module
            logger.log(Level.WARNING, "Skipping processing, module not initialized, file: {0}", abstractFile.getName());
            return ProcessResult.OK;
        }

        if ( ! isSupported(abstractFile)) {
            return ProcessResult.OK;
        }

        /**
         * hive_filename is a unique name suitable to exist in the root of the 
         *   module output directory.
         */    
        final String hive_filename = abstractFile.getName() + "_" + abstractFile.getId();
        
        /**
         * hive_extraction_directory is the absolute path of the hive_filename
         *   in the case and module specific output directory.
         */
        final String hive_extraction_directory = getExtractionDirectoryPathForFile(hive_filename);
        
        if ((new File(hive_extraction_directory)).exists()) {
            logger.log(Level.INFO, "Hive already has been processed as it has children and local unpacked file, skipping: {0}", abstractFile.getName());
            return ProcessResult.OK;
        }

        int hiveSize = (int)abstractFile.getSize();
        byte[] data = new byte[hiveSize];
        int bytesRead = 0;        
        try {
            // TODO(wb): Lazy to assume read returns all the requested bytes!            
            bytesRead += abstractFile.read(data, 0x0, hiveSize);
        } catch (TskException ex) {
            logger.log(Level.WARNING, "Failed to read hive content.", ex);
            // continue and parse out as much as we can
        }
        
        ByteBuffer buf = ByteBuffer.wrap(data);
        RegistryHive hive = new RegistryHiveBuffer(buf);
        final ProgressHandle progress = ProgressHandleFactory.createHandle(MODULE_NAME);
        ///< we use a counter here because its `final`, yet we'd like to use it in the following anonymous classes.
        final Counter processedItems = new Counter();

        progress.start(countCells(hive));
        
        // At the moment, we use recursion here with the `exploreHive` and 
        //   `process*` methods. This seems natural with a tree, but its really
        //   messy. For instance, the `KeyProcessor.process` method returns the
        //   newly created derivedFile, which is then used by exploreHive to
        //   build the tree. This is a code smell: we should be able to call 
        //   multiple instances of `KeyProcessor.process` on the tree.
        //
        // Anyways, I propose refactoring this into a non-recursive format.
        //   This might also give us an easier way to fix the file path bugs
        //   (name contains File.separator, and key and value names collide).
        
        exploreHive(hive, abstractFile, new KeyProcessor() {
            @Override
            public AbstractFile process(RegistryKey key, AbstractFile parentFile, String parentPath) throws KeyExplorationException {
                final String path;  ///< The Registry path of the key.
                final String fileName; ///< Simply the name of the key.
                try {
                    // TODO(wb): There's a problem here if a key/value name
                    //  contains the File.separator character. This definitely
                    //  happens in the wild.
                    fileName = key.getName();
                } catch (UnsupportedEncodingException ex) {
                    logger.log(Level.WARNING, "Error parsing registry hive (encoding)");
                    throw new KeyExplorationException();
                }
                path = parentPath + File.separator + fileName; 
                try {
                    dropLocalDirectory(hive_extraction_directory, path);
                } catch (PathAlreadyExistsException ex) {
                    // TODO(wb): Need to figure out what to do with this.
                    //   At first glance, it seems reasonable to just at a
                    //   postfix to the path that makes it unique. But this 
                    //   doesn't work for the children who continue to assume
                    //   the parent path is the same as the raw Registry path.
                    throw new KeyExplorationException(); // this is a fake exception to throw...
                }
                
                final long size = 0;
                final boolean isFile = false;
                final AbstractFile parent = parentFile;
                final long btime = 0;
                final long atime = 0;
                final long ctime = 0;
                
                DerivedFile df;
                try {
                    // since we are using File.separator to build paths, 
                    //   case directories are not portable.
                    final String relativePath = getCaseRelativeExtractionDirectoryPathForFile(hive_filename + File.separator + path);
                    df = fileManager.addDerivedFile(
                            fileName, 
                            relativePath, 
                            size,
                            ctime, btime, atime, key.getTimestamp().getTimeInMillis() / 1000,
                            isFile, 
                            parent, 
                            "", MODULE_NAME, "", "");
                } catch (TskCoreException ex) {
                    logger.log(Level.WARNING, "Error adding derived file");
                    throw new KeyExplorationException();
                }
                
                processedItems.increment();
                progress.progress(path, processedItems.getValue());
                
                // TODO(wb): don't do this on every single item
                List<AbstractFile> newFiles = new LinkedList<AbstractFile>();
                newFiles.add(df);
                WindowsRegistryInjestModule.this.sendNewFilesEvent(abstractFile, newFiles);
                WindowsRegistryInjestModule.this.rescheduleNewFiles(pipelineContext, newFiles);                
                
                return df;
            }
        }, new ValueProcessor() {
            @Override
            public AbstractFile process(RegistryValue value, AbstractFile parentFile, String parentPath) throws KeyExplorationException {
                final String path;  ///< The Registry path of the key.
                final String fileName;  ///< Simply the name of the value, or "(default)" if empty.
                try {
                    if ("".equals(value.getName())) {
                        fileName = "(default)";
                    } else {
                        // TODO(wb): see issue above on name containing the
                        //    File.separator character.
                        fileName = value.getName();
                    }
                } catch (UnsupportedEncodingException ex) {
                    logger.log(Level.WARNING, "Error parsing registry hive (encoding)");
                    throw new KeyExplorationException();
                }

                final ByteBuffer data;
                try {
                    data = value.getValue().getAsRawData();                    
                } catch (UnsupportedEncodingException ex) {
                    logger.log(Level.WARNING, "Error parsing registry hive (encoding)");
                    throw new KeyExplorationException();
                } catch (RegistryParseException ex) {
                    logger.log(Level.WARNING, "Error parsing registry hive (parse)");
                    throw new KeyExplorationException();
                }
                path = parentPath + File.separator + fileName;   

                try {
                    dropLocalFile(hive_extraction_directory, path, data);                
                } catch (PathAlreadyExistsException ex) {
                    // TODO(wb): see note in KeyProcessor about the bug here.
                    throw new KeyExplorationException(); // Fake exception to throw.
                }
                
                data.position(0x0);
                final long size = data.limit();                
                final boolean isFile = true;
                final AbstractFile parent = parentFile;
                final long btime = 0;
                final long atime = 0;
                final long ctime = 0;
                final long mtime = 0;  // only keys have modification timestamps.
                
                DerivedFile df;
                try {
                    final String relativePath = getCaseRelativeExtractionDirectoryPathForFile(hive_filename + File.separator + path);
                    df = fileManager.addDerivedFile(
                            fileName, 
                            relativePath, 
                            size,
                            ctime, btime, atime, mtime,
                            isFile, 
                            parent, 
                            "", MODULE_NAME, "", "");
                } catch (TskCoreException ex) {
                    logger.log(Level.WARNING, "Error adding derived file");
                    throw new KeyExplorationException();
                }                
                                
                processedItems.increment();
                progress.progress(path, processedItems.getValue());
                
                // TODO(wb): don't do this on every single item
                List<AbstractFile> newFiles = new LinkedList<AbstractFile>();
                newFiles.add(df);
                WindowsRegistryInjestModule.this.sendNewFilesEvent(abstractFile, newFiles);
                WindowsRegistryInjestModule.this.rescheduleNewFiles(pipelineContext, newFiles);

                return df;
            }
        });
        progress.finish();
        return ProcessResult.OK;
    }
    
    /**
     * dropLocalFile extracts the given content to the extraction directory using
     *   the provided derived path.
     * 
     * @param extractionDirectory The extraction directory.
     * @param derivedPath The derived path of the content to extract.
     * @param content The binary data that will be written to the file system.
     * @throws com.williballenthin.autopsy.wrim.WindowsRegistryInjestModule.PathAlreadyExistsException If the path already exists for a *key* with the same name.
     */
    private void dropLocalFile(String extractionDirectory, String derivedPath, ByteBuffer content) throws PathAlreadyExistsException {
        File localFile = new java.io.File(extractionDirectory + File.separator + derivedPath);

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
     * dropLocalDirectory extracts the given content to the extraction directory using
     *   the provided derived path.
     * 
     * @param extractionDirectory The extraction directory.
     * @param derivedPath The derived path of the content to extract.
     * @throws com.williballenthin.autopsy.wrim.WindowsRegistryInjestModule.PathAlreadyExistsException If the path already exists for a *value* with the same name.
     */    
    private void dropLocalDirectory(String extractionDirectory, String derivedPath) throws PathAlreadyExistsException {
        File localFile = new java.io.File(extractionDirectory + File.separator + derivedPath);
        
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

    /**
     * Trigger the events associated with new files.
     * @param hive The file from which new files were ultimately derived.
     * @param newFiles A list of new files.
     */
    private void sendNewFilesEvent(AbstractFile hive, List<AbstractFile> newFiles) {
        services.fireModuleContentEvent(new ModuleContentEvent(hive));
    }

    /**
     * Trigger events associated with new files.
     * @param pipelineContext The context of the ingest process.
     * @param newFiles A list of new files.
     */
    private void rescheduleNewFiles(PipelineContext<IngestModuleAbstractFile> pipelineContext, List<AbstractFile> newFiles) {
        for (AbstractFile newFile : newFiles) {
            services.scheduleFile(newFile, pipelineContext);
        }
    }
    
    // TODO(wb): I don't like that these return AbstractFiles that are subsequently used by unrelated logic (.exploreHive()).
    private abstract class KeyProcessor {
        /**
         * Process the given key and return the newly created derived file.
         * 
         * @param key The key to process.
         * @param parentPath The full key path of the parent key, with components separated by File.separator. 
         */
        public abstract AbstractFile process(RegistryKey key, AbstractFile parentFile, String parentPath) throws KeyExplorationException;
    }
    
    private abstract class ValueProcessor {
        /**
         * Process the given value and return the newly created derived file.
         * 
         * @param value The value to process.
         * @param parentPath The full key path of the parent key, with components separated by File.separator. 
         */
        public abstract AbstractFile process(RegistryValue value, AbstractFile parentFile, String parentPath) throws KeyExplorationException;
    }
    
    /**
     * An exception to throw when some localized error is encountered while
     *   processing a key or value.
     */
    private class KeyExplorationException extends Exception {
        public KeyExplorationException() {
            super();
        }
    }

    /**
     * Recursively explore a Registry hive, processing each node.
     * @param hive A hive that is to be explored.
     * @param kp A processor to handle keys.
     * @param vp A processor to handle values.
     */
    private void exploreHive(RegistryHive hive, AbstractFile hiveFile, KeyProcessor kp, ValueProcessor vp) {
        try {
            exploreKey(hive.getRoot(), hiveFile, "", kp, vp);
        } catch (RegistryParseException ex) {
            logger.log(Level.WARNING, "Error parsing registry hive");
            return;
        }
    }
    
    /**
     * Recursively explore a tree of keys and values, processing each node.
     * @param key A key that has not been explored yet.
     * @param parentPath The full key path of the parent key, with components separated by '/'.
     * @param kp A processor to handle keys.
     * @param vp A processor to handle values.
     */
    private void exploreKey(RegistryKey key, AbstractFile parentFile, String parentPath, KeyProcessor kp, ValueProcessor vp) {
        String path;
        try {
            path = parentPath + File.separator + key.getName();
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.WARNING, "Error parsing registry hive (encoding)");
            return;
        }
        
        AbstractFile thisFile;
        try {
            thisFile = kp.process(key, parentFile, parentPath);
        } catch (KeyExplorationException ex) {
            return;
        }
       
        try {     
            for (RegistryValue value : key.getValueList()) {
                vp.process(value, thisFile, path);
            }
        } catch (RegistryParseException ex) {
            logger.log(Level.WARNING, "Error parsing registry hive");
        } catch (KeyExplorationException ex) { 
            logger.log(Level.WARNING, "Error parsing registry hive");            
        }
       
        try {
            for (RegistryKey subkey : key.getSubkeyList()) {
                exploreKey(subkey, thisFile, path, kp, vp);
            }
        } catch (RegistryParseException ex) {
            logger.log(Level.WARNING, "Error parsing registry hive");
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
