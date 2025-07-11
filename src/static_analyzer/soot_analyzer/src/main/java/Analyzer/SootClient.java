package Analyzer;

import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;

public class SootClient {
    public final SetupApplication setupApplication;
    public final String apk;

    public SootClient(SootClientBuilder builder) {
        apk = builder.apk;
        InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
        config.getAnalysisFileConfig().setAndroidPlatformDir(builder.sdk); // ${ANDROID_HOME}/platforms
        config.getAnalysisFileConfig().setTargetAPKFile(builder.apk); // apk to analyze
        config.setMergeDexFiles(true); // try to analyze multiple dex files, not only classes.dex
        config.getAccessPathConfiguration().setAccessPathLength(-1); // don't constrain the max path length of access path, default is 5
        config.getSolverConfiguration().setMaxAbstractionPathLength(-1); // don't constrain the max path length of abstraction that may be propagated
        config.getPathConfiguration().setMaxCallStackSize(-1);
        config.getPathConfiguration().setMaxPathLength(-1); // don't constrain the max size for taint propagation paths
        this.setupApplication = new SetupApplication(config);
    }

    public static class SootClientBuilder {
        String apk = "";
        String sdk = "";
        String apiFile = "";


        public SootClientBuilder setApiFile(String apiFile) {
            this.apiFile = apiFile;
            return this;
        }

        public SootClientBuilder setApk(String apk) {
            this.apk = apk;
            return this;
        }

        public SootClientBuilder setSdk(String sdk) {
            this.sdk = sdk;
            return this;
        }

        public SootClient build() {
            return new SootClient(this);
        }
    }

}
