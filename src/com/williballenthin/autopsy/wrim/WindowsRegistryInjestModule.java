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
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import org.openide.util.Exceptions;
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
import org.sleuthkit.autopsy.ingest.IngestMonitor;
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
    private static final int ONE_HUNDRED_MEGABYTES = 1024 * 1024 * 100;
    private static final int MAX_HIVE_SIZE = ONE_HUNDRED_MEGABYTES;
    private static final int ONE_GIGABYTE = 1024 * 1024 * 1024;
    private static final int MIN_FREE_DISK_SPACE = ONE_GIGABYTE;
    private static final Logger logger = Logger.getLogger(WindowsRegistryInjestModule.class.getName());
    public static final String MODULE_NAME = "Windows Registry Extractor";
    public static final String MODULE_DESCRIPTION = "Extracts Windows Registry hives, reschedules them to current ingest and populates directory tree with keys and values.";
    final public static String MODULE_VERSION = "1.0";
    private IngestServices services;
    private volatile int messageID = 0;
    private int processedFiles = 0;
    private boolean initialized = false;
    private static WindowsRegistryInjestModule instance = null;
    //TODO use content type detection instead of extensions
    private String unpackDir; //relative to the case, to store in db
    private String unpackDirPath; //absolute, to extract to
    private FileManager fileManager;
   
    //private constructor to ensure singleton instance 
    private WindowsRegistryInjestModule() {
    }

    /**
     * Returns singleton instance of the module, creates one if needed
     *
     * @return instance of the module
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

        unpackDir = Case.getModulesOutputDirRelPath() + File.separator + MODULE_NAME;
        unpackDirPath = currentCase.getModulesOutputDirAbsPath() + File.separator + MODULE_NAME;

        fileManager = currentCase.getServices().getFileManager();

        File unpackDirPathFile = new File(unpackDirPath);
        if (!unpackDirPathFile.exists()) {
            try {
                unpackDirPathFile.mkdirs();
            } catch (SecurityException e) {
                logger.log(Level.SEVERE, "Error initializing output dir: " + unpackDirPath, e);
                String msg = "Error initializing " + MODULE_NAME;
                String details = "Error initializing output dir: " + unpackDirPath + ": " + e.getMessage();
                //MessageNotifyUtil.Notify.error(msg, details);
                services.postMessage(IngestMessage.createErrorMessage(++messageID, instance, msg, details));
                return;
            }
        }
        initialized = true;
    }

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
        
        byte[] header = new byte[0x4000];
        
        int bytesRead = 0;
        try {
            // TODO(wb): Lazy!
            bytesRead += abstractFile.read(header, 0x0, Math.min(0x4000, abstractFile.getSize()));
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, "Failed to read file content.", ex);
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
    
    private boolean isAlreadyUnpacked(AbstractFile abstractFile) {
        //check if already has derived files, skip
        try {
            if (abstractFile.hasChildren()) {
                //check if local unpacked dir exists
                final String localRootPath = getLocalRootRelPath(abstractFile);
                final String localRootAbsPath = getLocalRootAbsPath(localRootPath);
                if (new File(localRootAbsPath).exists()) {
                    return true;
                }
            }
        } catch (TskCoreException e) {
            logger.log(Level.INFO, "Error checking if hive already has been processed, skipping: {0}", abstractFile.getName());
            return false;
        }
        return false;
    }
    
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
            Exceptions.printStackTrace(ex);
        }
        return numItems;
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

        if (isAlreadyUnpacked(abstractFile)) {
            logger.log(Level.INFO, "Hive already has been processed as it has children and local unpacked file, skipping: {0}", abstractFile.getName());
            return ProcessResult.OK;
        }

        logger.log(Level.INFO, "Processing with " + MODULE_NAME + ": {0}", abstractFile.getName());
        ++processedFiles;


        byte[] data = new byte[(int)abstractFile.getSize()];
        
        // TODO(wb): Lazy!
        int bytesRead = 0;
        try {
            bytesRead += abstractFile.read(data, 0x0, abstractFile.getSize());
        } catch (TskException ex) {
            logger.log(Level.WARNING, "Failed to read hive content.", ex);
        }
        ByteBuffer buf = ByteBuffer.wrap(data);
        RegistryHive hive = new RegistryHiveBuffer(buf);
        
        List<AbstractFile> unpackedFiles = Collections.<AbstractFile>emptyList();
        final ProgressHandle progress = ProgressHandleFactory.createHandle(MODULE_NAME);
        final Counter processedItems = new Counter();
        final int numItems = countCells(hive);

        progress.start(numItems);
     
        final String localRootPath = getLocalRootRelPath(abstractFile);
        final String localRootAbsPath = getLocalRootAbsPath(localRootPath);
        
        exploreHive(hive, abstractFile, new KeyProcessor() {
            @Override
            public AbstractFile process(RegistryKey key, AbstractFile parentFile, String parentPath) throws KeyExplorationException {
                // TODO(wb): check path separators?
                final String fileName;
                final String path;
                try {
                    fileName = key.getName();
                } catch (UnsupportedEncodingException ex) {
                    logger.log(Level.WARNING, "Error parsing registry hive (encoding)");
                    throw new KeyExplorationException();
                }
                path = localRootPath + File.separator + fileName; // TODO(wb): separator
                dropLocalDirectory(localRootAbsPath, path);
                
                final long size = 0;
                final boolean isFile = false;
                final AbstractFile parent = parentFile;
                final long btime = 0;
                final long atime = 0;
                final long ctime = 0;
                
                DerivedFile df;
                try {
                    df = fileManager.addDerivedFile(fileName, path, size,
                            ctime, btime, atime, key.getTimestamp().getTimeInMillis() / 1000,
                            isFile, parent, "", MODULE_NAME, "", "");
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
                // TODO(wb): check path separators?
                final String path;
                final String fileName;
                try {
                    fileName = value.getName();
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
                path = localRootPath + File.separator + fileName;                
                dropLocalFile(localRootAbsPath, path, data);                
                data.position(0x0);
                final long size = data.limit();                
                final boolean isFile = true;
                final AbstractFile parent = parentFile;
                final long btime = 0;
                final long atime = 0;
                final long ctime = 0;
                final long mtime = 0;
                
                DerivedFile df;
                try {
                    df = fileManager.addDerivedFile(fileName, path, size,
                            ctime, btime, atime, mtime,
                            isFile, parent, "", MODULE_NAME, "", "");
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
    
    // TODO(wb): one of these must already exist somewhere
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
    
    private void dropLocalFile(String extractRootDirPath, String extractionPath, ByteBuffer content) {
        long freeDiskSpace = services.getFreeDiskSpace();
        content.position(0x0);
        final long size = content.limit();
        
        if (freeDiskSpace != IngestMonitor.DISK_FREE_SPACE_UNKNOWN && size > 0) { //if known free space and file not empty
            long newDiskSpace = freeDiskSpace - size;
            if (newDiskSpace < MIN_FREE_DISK_SPACE) {
                String msg = "Not enough disk space to unpack hive item: "  + extractionPath;
                String details = "The archive item is too large to unpack, skipping unpacking this item. ";
                services.postMessage(IngestMessage.createErrorMessage(++messageID, instance, msg, details));
                logger.log(Level.INFO, "Skipping Hive item due not sufficient disk space for this item: {0}", extractionPath);
                return;
            } else {
                // update est. disk space during this archive, so we don't need to poll for every file extracted
                // TODO(wb): really, just do this once at the start, ensure hive isnt too large.
                // freeDiskSpace = newDiskSpace;
            }
        }

        final String localFileRelPath = extractRootDirPath + File.separator + extractionPath;
        final String localAbsPath = unpackDirPath + File.separator + localFileRelPath;

        //create local dirs and empty files before extracted
        File localFile = new java.io.File(localAbsPath);
        //cannot rely on files in top-bottom order
        if (!localFile.exists()) {
            try {
                localFile.getParentFile().mkdirs();
                try {
                    localFile.createNewFile();
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, "Error creating extracted file: " + localFile.getAbsolutePath(), ex);
                }
            } catch (SecurityException e) {
                logger.log(Level.SEVERE, "Error setting up output path for unpacked file: {0}", extractionPath);
                // TODO(wb): consider bail out / msg to the user
            }
            // TODO(wb): write file contents
        }
    }
    
    private void dropLocalDirectory(String extractRootDirPath, String extractionPath) {
        final String localFileRelPath = extractRootDirPath + File.separator + extractionPath;
        final String localAbsPath = unpackDirPath + File.separator + localFileRelPath;

        File localFile = new java.io.File(localAbsPath);
        //cannot rely on files in top-bottom order
        if (!localFile.exists()) {
            try {
                localFile.mkdirs();
            } catch (SecurityException e) {
                logger.log(Level.SEVERE, "Error setting up output path for unpacked file: {0}", extractionPath);
                // TODO(wb): consider bail out / msg to the user
            }
        }
    }

    private void sendNewFilesEvent(AbstractFile hive, List<AbstractFile> newFiles) {
        services.fireModuleContentEvent(new ModuleContentEvent(hive));
    }

    private void rescheduleNewFiles(PipelineContext<IngestModuleAbstractFile> pipelineContext, List<AbstractFile> newFiles) {
        for (AbstractFile newFile : newFiles) {
            services.scheduleFile(newFile, pipelineContext);
        }
    }

    /**
     * Get local relative path to the unpacked hive root
     *
     * @param archiveFile
     * @return A local relative path as a string.
     */
    private String getLocalRootRelPath(AbstractFile hive) {
        return hive.getName() + "_" + hive.getId();
    }

    /**
     * Get local abs path to the unpacked hive root
     *
     * @param localRootRelPath relative path to archive, from
     * getLocalRootRelPath()
     * @return A local absolute path as a string.
     */
    private String getLocalRootAbsPath(String localRootRelPath) {
        return unpackDirPath + File.separator + localRootRelPath;
    }
    
    private abstract class KeyProcessor {
        /**
         * Process the given key.
         * @param key The key to process.
         * @param parentPath The full key path of the parent key, with components separated by '/'. 
         */
        public abstract AbstractFile process(RegistryKey key, AbstractFile parentFile, String parentPath) throws KeyExplorationException;
    }
    
    private abstract class ValueProcessor {
        /**
         * Process the given value.
         * @param value The value to process.
         * @param parentPath The full key path of the parent key, with components separated by '/'. 
         */
        public abstract AbstractFile process(RegistryValue value, AbstractFile parentFile, String parentPath) throws KeyExplorationException;
    }
    
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
            path = parentPath + key.getName();
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
