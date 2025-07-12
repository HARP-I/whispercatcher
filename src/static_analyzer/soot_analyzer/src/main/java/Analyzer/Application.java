package Analyzer;

import Analyzer.Deserialization.ApkTrafficKeywordsInfo;
import Analyzer.Deserialization.TrafficInfo;
import Analyzer.Representation.ResultCell;
import Analyzer.Utils.FileIOUtils;
import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Options;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Scene;
import soot.SootClass;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class Application {
    private static final Logger logger = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) throws Exception {
        Options options = new Options();
        options.addOption("apk", true, "apk path");
        options.addOption("sdk", true, "sdk path");
        options.addOption("input", true, "input path"); // traffic keywords
        options.addOption("output", true, "output path"); // key-apis extracted
        options.addOption("chainsLimit", true, "call chains limit, -1 for no limit");

        CommandLineParser commandLineParser = new BasicParser();
        CommandLine commandLine = commandLineParser.parse(options, args);
        String apk = commandLine.getOptionValue("apk");
        String sdk = commandLine.getOptionValue("sdk");
        String input = commandLine.getOptionValue("input");
        String output = commandLine.getOptionValue("output");
        int chainsLimit = Integer.parseInt(commandLine.getOptionValue("chainsLimit", "-1"));

        SootClient.SootClientBuilder builder = new SootClient.SootClientBuilder();
        SootClient sootClient = builder
                .setSdk(sdk)
                .setApk(apk)
                .build();
        List<SootClass> sootClassList = new ArrayList<>(1000);
        sootClassList.addAll(Scene.v().getClasses());
        logger.info("Current apk: {}, {} classes loaded.", apk, sootClassList.size());
        int total = sootClassList.size();
        int eachSlice = total / Executor.PROCESSORS_AVAILABLE;
        CountDownLatch latch = Executor.initLatch();
        // split classes into slices and submit them into the executor
        for (int i = 0; i < Executor.PROCESSORS_AVAILABLE; ++i) {
            int fromIndex = i * eachSlice;
            int toIndex = (i == total) ? total : (i + 1) * eachSlice;
            Executor.submit(new PreProcessor(sootClient.apk, sootClassList.subList(fromIndex, toIndex), latch));
        }
        try {
            latch.await();
            Executor.shutDown();
            Executor.awaitTermination(60, TimeUnit.SECONDS);
            PreProcessor.propagateStaticStringsFromInitStringRelatedMethod();

            // obtained cgs and static <strings, methodParser> map
            List<Map<String, List<ResultCell>>> resultCallChains = new ArrayList<>();
            ApkTrafficKeywordsInfo apkTrafficKeywordsInfo = FileIOUtils.getApkTrafficKeywordsFromJson(input);
            // all traffic flows of one apk
            for (TrafficInfo trafficInfo : apkTrafficKeywordsInfo.getFlows()) {
                EncryptionAnalysisProcessor encryptionAnalysisProcessor = new EncryptionAnalysisProcessor(apkTrafficKeywordsInfo.getPkgName(), trafficInfo); // for each traffic
                encryptionAnalysisProcessor.encryptionAnalysis();
                resultCallChains.add(encryptionAnalysisProcessor.getTopWeightResultCell(chainsLimit));
            }
            FileIOUtils.dumpToJson(output, resultCallChains); // dump key-apis to json file
            logger.info("Analyzer finished.");
        } catch (Exception e) {
            logger.error("Application: {}", e.toString());
            throw e;
        }
    }
}
