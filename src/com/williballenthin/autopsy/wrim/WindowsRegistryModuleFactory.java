package com.williballenthin.autopsy.wrim;

import org.openide.util.NbBundle;
import org.openide.util.lookup.ServiceProvider;
import org.sleuthkit.autopsy.coreutils.Version;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.IngestModuleFactoryAdapter;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;

@ServiceProvider(service = IngestModuleFactory.class)
public class WindowsRegistryModuleFactory extends IngestModuleFactoryAdapter {

    public static final String MODULE_VERSION = "1.0";
    static String getModuleName() {
        return NbBundle.getMessage(WindowsRegistryInjestModule.class, "WindowsRegistryModule.moduleName");
    }

    @Override
    public String getModuleDisplayName() {
        return getModuleName();
    }

    @Override
    public String getModuleDescription() {
        return NbBundle.getMessage(WindowsRegistryInjestModule.class, "WindowsRegistryModule.moduleDesc");
    }

    @Override
    public String getModuleVersionNumber() {
        return MODULE_VERSION;
    }

    @Override
    public boolean isFileIngestModuleFactory() {
        return true;
    }

    @Override
    public FileIngestModule createFileIngestModule(IngestModuleIngestJobSettings ingestOptions) {
        return new WindowsRegistryInjestModule();
    }
}