/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.williballenthin.autopsy.wrim;

import com.williballenthin.rejistry.RegistryKey;
import com.williballenthin.rejistry.RegistryParseException;
import com.williballenthin.rejistry.RegistryValue;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;
import org.netbeans.api.progress.ProgressHandle;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.autopsy.ingest.ModuleContentEvent;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.DerivedFile;
import org.sleuthkit.datamodel.TskCoreException;

class NewDerivedFileHandler {
    private final int BATCH_SIZE = 100;
    private final String _moduleName;
    private final Counter _processedItems;
    private final ProgressHandle _progress;
    private final IngestJobContext _ingestJobContext;
    private final AbstractFile _hiveFile;   
    private final FileManager _fileManager;
    private IngestServices _services;
    private  List<AbstractFile> _newFiles;            
    
public NewDerivedFileHandler(String moduleName, ProgressHandle progress, 
            Counter processedItems, 
            IngestJobContext ingestJobContext,
            FileManager fileManager, IngestServices services, 
            AbstractFile hiveFile) {
        this._progress = progress;
        this._processedItems = processedItems;
        this._newFiles = new LinkedList<AbstractFile>();
        this._ingestJobContext = ingestJobContext;
        this._hiveFile = hiveFile;
        this._fileManager = fileManager;
        this._services = services;
        this._moduleName = moduleName;
    }

    public void commit() {
        synchronized(this) {
            this._ingestJobContext.addFilesToJob(this._newFiles);
            this._services.fireModuleContentEvent(new ModuleContentEvent(this._hiveFile));                      
            this._newFiles = new LinkedList<AbstractFile>();
        }                
    }

    private void handleNewFileAdded() {
        if (this._newFiles.size() > BATCH_SIZE) {
            this.commit();
        }
    }

    private AbstractFile addNew(String name, String fsPath, long size, long mtime, boolean isFile, AbstractFile parent) throws FailedToAddDerivedFileException {
        DerivedFile df;
        try {
            df = this._fileManager.addDerivedFile(
                    name, 
                    fsPath, 
                    size,
                    0, 0, 0, mtime,
                    isFile, 
                    parent, 
                    "", this._moduleName, "", "");
        } catch (TskCoreException ex) {
            throw new FailedToAddDerivedFileException();
        }

        this._processedItems.increment();
        this._progress.progress(name, this._processedItems.getValue());

        this.handleNewFileAdded();  
        return df;
    }

    /**
     * @param fsPath The case and module relative path to the extracted file. 
     */
    public AbstractFile addNewKey(RegistryKey key, AbstractFile parent, String name, String fsPath) throws FailedToAddDerivedFileException {
        return this.addNew(name, fsPath, 0, key.getTimestamp().getTimeInMillis() / 1000, false, parent);
    }

    /**
     * @param fsPath The case and module relative path to the extracted file. 
     */
    public AbstractFile addNewValue(RegistryValue value, AbstractFile parent, String name, String fsPath) throws FailedToAddDerivedFileException {
        final ByteBuffer data;
        try {
            data = value.getValue().getAsRawData();                    
        } catch (UnsupportedEncodingException ex) {
            throw new FailedToAddDerivedFileException();
        } catch (RegistryParseException ex) {
            throw new FailedToAddDerivedFileException();                    
        }
        data.position(0x0);
        return this.addNew(name, fsPath, data.limit(), 0, true, parent);
    }
}    
