package Analyzer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.cfg.LibraryClassPatcher;
import soot.jimple.toolkits.ide.icfg.BiDiInterproceduralCFG;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;
import soot.options.Options;
import soot.toolkits.graph.DirectedGraph;
import soot.toolkits.graph.PseudoTopologicalOrderer;

import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SetupApplication extends soot.jimple.infoflow.android.SetupApplication {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private static BiDiInterproceduralCFG<Unit, SootMethod> cfg = null;
    private static final Map<SootMethod, List<Unit>> orderedListCache = new HashMap<>();


    public SetupApplication(InfoflowAndroidConfiguration config) {
        super(config);
        try {
            this.initializeSoot();
            try {
                this.parseAppResources();
            } catch (Exception e) {
                logger.error("SetupApplication - parsing app resources failed, may be this is one sub-apk or invalid apk.");
            }
            PackManager.v().getPack("cg").apply();
            cfg = new JimpleBasedInterproceduralCFG(true);
        } catch (Exception e) {
            logger.error("SetupApplication: init error, {}", e.toString());
        }
    }

    // initializeSoot -> same logic with the super private method
    private void initializeSoot() {
        logger.info("Initializing Soot...");

        final String androidJar = config.getAnalysisFileConfig().getAndroidPlatformDir();
        final String apkFileLocation = config.getAnalysisFileConfig().getTargetAPKFile();

        // Clean up any old Soot instance we may have
        G.reset();

        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_allow_phantom_refs(true);
        if (config.getWriteOutputFiles())
            Options.v().set_output_format(Options.output_format_jimple);
        else
            Options.v().set_output_format(Options.output_format_none);
        Options.v().set_whole_program(true);
        Options.v().set_process_dir(Collections.singletonList(apkFileLocation));
        if (forceAndroidJar)
            Options.v().set_force_android_jar(androidJar);
        else
            Options.v().set_android_jars(androidJar);
        Options.v().set_src_prec(Options.src_prec_apk_class_jimple);
        Options.v().set_keep_offset(false);
        Options.v().set_keep_line_number(config.getEnableLineNumbers());
        Options.v().set_throw_analysis(Options.throw_analysis_dalvik);
        Options.v().set_process_multiple_dex(config.getMergeDexFiles());
        Options.v().set_ignore_resolution_errors(true);

        // Set soot phase option if original names should be used
        if (config.getEnableOriginalNames())
            Options.v().setPhaseOption("jb", "use-original-names:true");

        // Set the Soot configuration options. Note that this will needs to be
        // done before we compute the classpath.
        if (sootConfig != null)
            sootConfig.setSootOptions(Options.v(), config);

        Options.v().set_soot_classpath(getClasspath());
        Main.v().autoSetOptions();
        configureCallgraph();

        // Load whatever we need
        logger.info("Loading dex files...");
        Scene.v().loadNecessaryClasses();
        // Make sure that we have valid Jimple bodies
        PackManager.v().getPack("wjpp").apply();

        // Patch the callgraph to support additional edges. We do this now,
        // because during callback discovery, the context-insensitive callgraph
        // algorithm would flood us with invalid edges.
        LibraryClassPatcher patcher = getLibraryClassPatcher();
        patcher.patchLibraries();
    }

    private String getClasspath() {
        final String androidJar = config.getAnalysisFileConfig().getAndroidPlatformDir();
        final String apkFileLocation = config.getAnalysisFileConfig().getTargetAPKFile();
        final String additionalClasspath = config.getAnalysisFileConfig().getAdditionalClasspath();

        String classpath = forceAndroidJar ? androidJar : Scene.v().getAndroidJarPath(androidJar, apkFileLocation);
        if (additionalClasspath != null && !additionalClasspath.isEmpty())
            classpath += File.pathSeparator + additionalClasspath;
        logger.debug("soot classpath: {}", classpath);
        return classpath;
    }

    // backward dataflow graph
    public static List<Unit> getOrderedListOf(SootMethod sootMethod, boolean doCache) {
        List<Unit> res;
        if ((res = orderedListCache.get(sootMethod)) != null) {
            return res;
        }
        DirectedGraph<Unit> controlGraphOfBody = cfg.getOrCreateUnitGraph(sootMethod);
        res = new PseudoTopologicalOrderer<Unit>().newList(controlGraphOfBody, true);
        if (doCache) {
            orderedListCache.put(sootMethod, res);
        }
        return res;
    }

}
