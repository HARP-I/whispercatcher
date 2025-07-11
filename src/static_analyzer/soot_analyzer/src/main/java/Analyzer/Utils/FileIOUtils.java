package Analyzer.Utils;

import Analyzer.Deserialization.ApkTrafficKeywordsInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class FileIOUtils {
    public static final ObjectMapper mapper = new ObjectMapper();
    private static final Logger logger = LoggerFactory.getLogger(FileIOUtils.class);

    public static void dumpToJson(String outputPath, Object value) {
        try {
            File out = new File(outputPath);
            if (out.createNewFile()) {
                logger.info("FileIOUtils.dumpToJson: File {} doesn't exist, created a new one.", outputPath);
            } else {
                logger.info("FileIOUtils.dumpToJson: File {} already exists.", outputPath);
            }
            mapper.writerWithDefaultPrettyPrinter().writeValue(out, value);
        } catch (Exception e) {
            logger.error("FileIOUtils.dumpToJson: {}", e.toString());
        }
    }

    public static ApkTrafficKeywordsInfo getApkTrafficKeywordsFromJson(String flowKeywordsFilePath) {
        File file = new File(flowKeywordsFilePath);
        if (!file.isFile()) {
            throw new RuntimeException("no traffic keywords file found!");
        }
        try {
            return mapper.readValue(file, ApkTrafficKeywordsInfo.class); // json to java object ApkTrafficKeywordsInfo
        } catch (Exception e) {
            logger.error("FileIOUtils.getApkFromJson: {}", e.toString());
            throw new RuntimeException("cannot read traffic keywords file!");
        }
    }

}
