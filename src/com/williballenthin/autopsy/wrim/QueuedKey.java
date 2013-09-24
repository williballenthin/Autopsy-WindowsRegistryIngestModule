package com.williballenthin.autopsy.wrim;

import com.williballenthin.rejistry.RegistryKey;
import org.sleuthkit.datamodel.AbstractFile;

class QueuedKey {
    public final AbstractFile parentFile;
    public final String parentRegistryPath;
    public final String parentFileSystemPath;
    public final RegistryKey key;
    
    public QueuedKey(AbstractFile parentFile, String parentRegistryPath, String parentFileSystemPath, RegistryKey key) {
        this.parentFile = parentFile;
        this.parentRegistryPath = parentRegistryPath;
        this.parentFileSystemPath = parentFileSystemPath;
        this.key = key;
    }
}
