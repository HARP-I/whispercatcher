package Analyzer;

import Analyzer.Deserialization.TrafficInfo;
import Analyzer.Representation.Edge;
import Analyzer.Representation.MethodParser;
import Analyzer.Representation.MethodParserWithDepth;
import Analyzer.Representation.ResultCell;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class EncryptionAnalysisProcessor {
    static Logger logger = LoggerFactory.getLogger(EncryptionAnalysisProcessor.class);

    String packageName;
    public TrafficInfo trafficInfo;
    public Map<MethodParser, ResultCell> resultCellMap; // method: resultCell, resultCell:


    public EncryptionAnalysisProcessor(String packageName, TrafficInfo trafficInfo) {
        this.packageName = packageName;
        this.trafficInfo = trafficInfo;
        this.resultCellMap = new HashMap<>();
    }

    public void encryptionAnalysis() {
        Set<String> keywordRelatedStrings = getKeywordRelatedStrings();
        Set<String> doubleWeightKeywordRelatedStrings = getDoubleWeightKeywordRelatedStrings();
        Set<String> unionSet = new HashSet<>(keywordRelatedStrings);
        unionSet.addAll(doubleWeightKeywordRelatedStrings);

        for (String staticStr : unionSet) {
            // searching for methods related to candidate keys
            Set<MethodParser> candidateMethodParsers = PreProcessor.staticStringsMethodsMap.get(staticStr);
            // for each candidateMethod, upstream and downstream query encryption methods
            for (MethodParser candidateMethodParser : candidateMethodParsers) {
                // dfs search for one chain from candidate method to encryption method, corresponding results are added to resultCellMap
                DFSVisitor dfsVisitor = new DFSVisitor(candidateMethodParser, staticStr, resultCellMap, trafficInfo, keywordRelatedStrings, doubleWeightKeywordRelatedStrings);
                dfsVisitor.dfs(new Edge(candidateMethodParser), new MethodParserWithDepth(candidateMethodParser, 1));
                // BFSVisitor bfsVisitor = new BFSVisitor(candidateMethodParser, staticStr, resultCellMap, trafficInfo, keywordRelatedStrings, doubleWeightKeywordRelatedStrings);
                // bfsVisitor.bfs(candidateMethodParser);
            }
        }
        logger.info("Encryption analysis succeed.");
    }

    private List<String> getCandidateKeywords(String keyword) {
        List<String> candidateKeywords = new ArrayList<>(trafficInfo.getKeys().size());
        if (trafficInfo.getKeys().contains(keyword)) {
            candidateKeywords.add(keyword); // extract keywords that both contained in traffic keywords file and apk
        }
        if (trafficInfo.getDoubleWeightKeys().contains(keyword)) {
            candidateKeywords.add(keyword); // extract double weight keywords that both contained in traffic keywords file and apk
        }
        return candidateKeywords;
    }

    private Set<String> getKeywordRelatedStrings() {
        Set<String> res = new HashSet<>();
        for (String staticStr : PreProcessor.staticStringsMethodsMap.keySet()) {
            for (String trafficKeyword : trafficInfo.getKeys()) {
                if (trafficKeyword.length() >= 3) {
                    if (staticStr.toLowerCase().startsWith(trafficKeyword.toLowerCase()) || staticStr.toLowerCase().endsWith(trafficKeyword.toLowerCase())) {
                        res.add(staticStr);
                        break;
                    }
                }
                if (staticStr.contains(trafficKeyword) && Math.abs(staticStr.length() - trafficKeyword.length()) < 3) { // length difference < 3
                    res.add(staticStr);
                    break;
                }
            }
        }
        return res;
    }

    private Set<String> getDoubleWeightKeywordRelatedStrings() {
        Set<String> res = new HashSet<>();
        for (String staticStr : PreProcessor.staticStringsMethodsMap.keySet()) {
            int urlPartsCounter = 0;
            for (String trafficKeyword : trafficInfo.getDoubleWeightKeys()) {
                if (trafficKeyword.length() >= 3) {
                    if (staticStr.toLowerCase().startsWith(trafficKeyword.toLowerCase()) || staticStr.toLowerCase().endsWith(trafficKeyword.toLowerCase())) {
                        res.add(staticStr);
                        break;
                    }
                }
                if (staticStr.contains(trafficKeyword) && Math.abs(staticStr.length() - trafficKeyword.length()) < 3) {
                    res.add(staticStr);
                    break;
                } else if (staticStr.contains(trafficKeyword) && trafficKeyword.length() >= 2) { // static string is one url, but trafficKeyword is a part-word
                    urlPartsCounter += 1;
                }
            }
            if (urlPartsCounter > 1) res.add(staticStr);
        }
        return res;
    }

    public Map<String, List<ResultCell>> getTopWeightResultCell(int num) {
        HashMap<String, List<ResultCell>> ret = new HashMap<>();
        PriorityQueue<ResultCell> rankQ = new PriorityQueue<>(resultCellMap.values());
        if (num == 0 || resultCellMap.isEmpty()) return ret;
        else if (num > 0) {
            num = Math.min(num, resultCellMap.size());
            List<ResultCell> topResultCells = new ArrayList<>();
            for (int i = 0; i < num; i++) {
                ResultCell resultCell = rankQ.poll(); // head of the queue
                topResultCells.add(resultCell);
            }
            ret.put(trafficInfo.getId(), topResultCells);
            return ret;
        }
        // all call chains
        ret.put(trafficInfo.getId(), getAllResultCells());
        return ret;
    }

    public List<ResultCell> getAllResultCells() {
        return new ArrayList<>(resultCellMap.values());
    }

}

class DFSVisitor {
    public final Set<Edge> visitedEdges = new HashSet<>();
    public final Deque<Edge> paths = new ArrayDeque<>();
    public final MethodParser candidateMethodParser;
    public final String keyword;
    public final Map<MethodParser, ResultCell> resultCellMap;
    public TrafficInfo trafficInfo;
    public Set<String> keywordRelatedStrings;
    public Set<String> doubleWeightedRelatedStrings;

    public DFSVisitor(MethodParser candidateMethodParser, String keyword, Map<MethodParser, ResultCell> resultCellMap, TrafficInfo trafficInfo, Set<String> keywordRelatedStrings, Set<String> doubleWeightedRelatedStrings) {
        this.candidateMethodParser = candidateMethodParser;
        this.keyword = keyword;
        this.resultCellMap = resultCellMap;
        this.trafficInfo = trafficInfo;
        this.keywordRelatedStrings = keywordRelatedStrings;
        this.doubleWeightedRelatedStrings = doubleWeightedRelatedStrings;
    }


    public void dfs(Edge lastEdge, MethodParserWithDepth methodParserWithDepth) {
        if (visitedEdges.contains(lastEdge)) {
            return;
        }
        MethodParser curMethodParser = methodParserWithDepth.methodParser;
        int curDepth = methodParserWithDepth.depth;
        visitedEdges.add(lastEdge);
        paths.push(lastEdge);
        MethodParser encMethodParser = MethodParser.encMethods.get(curMethodParser.sootMethod);
        // check if current method is encryption method, if true, we find one chain
        if (encMethodParser != null) {
            resultCellMap.put(candidateMethodParser, new ResultCell(candidateMethodParser, new ArrayList<>(paths), keyword, trafficInfo, calcChainScore()));
        }
        // downstream
        for (MethodParser nextMethodParser : curMethodParser.next) {
            dfs(new Edge(curMethodParser, nextMethodParser), new MethodParserWithDepth(nextMethodParser, curDepth + 1));
        }
        paths.pop(); // backtrack
    }

    private int calcChainScore() {
        int score = 0;
        Set<MethodParser> visitedMethodParsers = new HashSet<>();
        for (Edge edge : paths) {
            visitedMethodParsers.add(edge.source);
            visitedMethodParsers.add(edge.target);
        }
        // methods contain regular keywords
        for (String staticStr: keywordRelatedStrings) {
            Set<MethodParser> methodParsers = PreProcessor.staticStringsMethodsMap.get(staticStr);
            if (methodParsers != null) {
                score += (int) methodParsers.stream().filter(visitedMethodParsers::contains).count();
            }
        }
        // methods contain double weight keywords
        for (String staticStr: doubleWeightedRelatedStrings) {
            Set<MethodParser> methodParsers = PreProcessor.staticStringsMethodsMap.get(staticStr);
            if (methodParsers != null) {
                score += (int) methodParsers.stream().filter(visitedMethodParsers::contains).count() * 2;
            }
        }
        return score;
    }
}

class BFSVisitor {
    public final Set<Edge> visitedEdges = new HashSet<>();
    public final MethodParser candidateMethodParser;
    public final String keyword;
    public final Map<MethodParser, ResultCell> resultCellMap;
    public final TrafficInfo trafficInfo;
    public Set<String> keywordRelatedStrings;
    public Set<String> doubleWeightedRelatedStrings;

    public BFSVisitor(MethodParser candidateMethodParser, String keyword, Map<MethodParser, ResultCell> resultCellMap, TrafficInfo trafficInfo, Set<String> keywordRelatedStrings, Set<String> doubleWeightedRelatedStrings) {
        this.candidateMethodParser = candidateMethodParser;
        this.keyword = keyword;
        this.resultCellMap = resultCellMap;
        this.trafficInfo = trafficInfo;
        this.keywordRelatedStrings = keywordRelatedStrings;
        this.doubleWeightedRelatedStrings = doubleWeightedRelatedStrings;
    }

    // save path info from queue
    static class PathNode {
        MethodParser curMethodParser;
        List<Edge> path;  // edges in the path
        PathNode(MethodParser curMethodParser, List<Edge> path) {
            this.curMethodParser = curMethodParser;
            this.path = path;
        }
    }

    public void bfs(MethodParser startMethodParser) {
        Queue<PathNode> queue = new LinkedList<>();
        queue.offer(new PathNode(startMethodParser, new ArrayList<>()));

        while (!queue.isEmpty()) {
            PathNode node = queue.poll();
            MethodParser curMethodParser = node.curMethodParser;
            List<Edge> curPath = node.path;

            // out edges of current method parser
            for (MethodParser nextMethodParser : curMethodParser.next) {
                Edge edge = new Edge(curMethodParser, nextMethodParser);
                if (visitedEdges.contains(edge)) {
                    continue;
                }
                visitedEdges.add(edge);

                // add current edge to path
                List<Edge> newPath = new ArrayList<>(curPath);
                newPath.add(edge);

                // check if next method is encryption method
                MethodParser encMethodParser = MethodParser.encMethods.get(nextMethodParser.sootMethod);
                if (encMethodParser != null) {
                    resultCellMap.put(candidateMethodParser, new ResultCell(candidateMethodParser, newPath, keyword, trafficInfo, calcChainScore(newPath)));
                }
                // enqueue next method parser with updated path
                queue.offer(new PathNode(nextMethodParser, newPath));
            }
        }
    }
    private int calcChainScore(List<Edge> paths) {
        int score = 0;
        Set<MethodParser> visitedMethodParsers = new HashSet<>();
        for (Edge edge : paths) {
            visitedMethodParsers.add(edge.source);
            visitedMethodParsers.add(edge.target);
        }
        // methods contain regular keywords
        for (String staticStr: keywordRelatedStrings) {
            Set<MethodParser> methodParsers = PreProcessor.staticStringsMethodsMap.get(staticStr);
            if (methodParsers != null) {
                score += (int) methodParsers.stream().filter(visitedMethodParsers::contains).count();
            }
        }
        // methods contain double weight keywords
        for (String staticStr: doubleWeightedRelatedStrings) {
            Set<MethodParser> methodParsers = PreProcessor.staticStringsMethodsMap.get(staticStr);
            if (methodParsers != null) {
                score += (int) methodParsers.stream().filter(visitedMethodParsers::contains).count() * 2;
            }
        }
        return score;
    }
}