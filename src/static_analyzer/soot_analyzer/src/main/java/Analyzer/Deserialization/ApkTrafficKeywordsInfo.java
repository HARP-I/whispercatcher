package Analyzer.Deserialization;

import lombok.Data;

import java.util.List;

@Data
public class ApkTrafficKeywordsInfo {
    private String apkId;

    private String pkgName;

    private String pkgPath;

    private List<TrafficInfo> flows; // info about all traffic entries: { id, url, content, method, keys }

}
