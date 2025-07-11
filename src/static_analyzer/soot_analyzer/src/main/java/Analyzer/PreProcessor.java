package Analyzer;

import Analyzer.Representation.MethodParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

import static Analyzer.SetupApplication.getOrderedListOf;
import static Analyzer.Utils.StringUtils.stringify;

public class PreProcessor implements Runnable {
    static Logger logger = LoggerFactory.getLogger(PreProcessor.class);
    public String apk;
    public List<SootClass> classesSliced;
    private final CountDownLatch latch;
    public static Map<String, Set<MethodParser>> staticStringsMethodsMap = new ConcurrentHashMap<>(); // apk methods that contain static strings, keywords: methodSet
    public static Map<MethodParser, Map<String, Set<String>>> initFiledsMap = new ConcurrentHashMap<>(); // init method parser to (init field -> static strings)
    public static Map<MethodParser, Set<String>> initStringRelatedMethodsMap = new HashMap<>(); // methods that contain init strings

    public PreProcessor(String apk, List<SootClass> classesSliced, CountDownLatch latch) {
        this.apk = apk;
        this.latch = latch;
        this.classesSliced = classesSliced;
    }

    public void run() {
        try {
            for (SootClass sootClass : classesSliced) {
                for (SootMethod sootMethod : sootClass.getMethods()) {
                    Body body = getBody(sootMethod);
                    if (null == body) {
                        continue;
                    }
                    MethodParser curMethodParser = MethodParser.getMethodParserOf(sootMethod);
                    boolean isInitMethod = sootMethod.getName().equals("<clinit>") || sootMethod.getName().equals("<init>");
                    for (Unit u : getOrderedListOf(sootMethod, false)) {
                        if (u instanceof Stmt) {
                            Stmt stmt = (Stmt) u;
                            if (stmt.containsInvokeExpr()) {
                                InvokeExpr invokeExpr = stmt.getInvokeExpr();
                                SootMethod callee = invokeExpr.getMethod();
                                MethodParser calleeMethodParser = MethodParser.getMethodParserOf(callee);
                                // call relationship construction
                                curMethodParser.setPreNextRelation(calleeMethodParser);
                                // mark encryption methods
                                if (isEncryptMethod(callee.getName())) {
                                    calleeMethodParser.markEncMethod();
                                }
                                // static string: method invocation args
                                for (Value arg : invokeExpr.getArgs()) {
                                    if (arg instanceof StringConstant) {
                                        String argString = stringify(arg.toString());
                                        putStaticString(argString, curMethodParser);
                                    }
                                }
                            }
                            // static string: assignment
                            if (stmt instanceof AssignStmt) {
                                AssignStmt assignStmt = (AssignStmt) stmt;
                                Value rightOp = assignStmt.getRightOp();
                                if (rightOp instanceof StringConstant) {
                                    String right = stringify(rightOp.toString());
                                    putStaticString(right, curMethodParser);
                                }
                            }
                            // find fields assignment in init methods
                            if (stmt instanceof AssignStmt && isInitMethod) {
                                // init methods: static strings in the field initialization
                                AssignStmt assignStmt = (AssignStmt) stmt;
                                Value leftOp = assignStmt.getLeftOp();
                                Value rightOp = assignStmt.getRightOp();
                                if (leftOp instanceof FieldRef && rightOp instanceof StringConstant) {
                                    FieldRef fieldRef = (FieldRef) leftOp;
                                    String fieldName = fieldRef.getField().getName();
                                    String right = stringify(rightOp.toString());
                                    addToInitFieldsMap(curMethodParser, fieldName, Collections.singleton(right));
                                } else if (leftOp instanceof FieldRef && stmt.containsInvokeExpr()) {
                                    InvokeExpr invokeExpr = stmt.getInvokeExpr();
                                    FieldRef fieldRef = (FieldRef) leftOp;
                                    String fieldName = fieldRef.getField().getName();
                                    Set<String> stmtStrings = new HashSet<>();
                                    for (Value arg : invokeExpr.getArgs()) {
                                        if (arg instanceof StringConstant) {
                                            String argString = stringify(arg.toString());
                                            stmtStrings.add(argString);
                                        }
                                    }
                                    addToInitFieldsMap(curMethodParser, fieldName, stmtStrings);
                                }
                            }
                        }
                    }
                }
            }
            logger.info("[Finished] put static strings in the pre-processor finished.");
        } catch (Exception e) {
            logger.error("error occurred: {}", e.toString());
        } finally {
            latch.countDown();
        }
    }

    public static void putStaticString(String str, MethodParser methodParser) {
        Set<MethodParser> methodParsers = staticStringsMethodsMap.computeIfAbsent(str, k -> new HashSet<>()); // check if s is in the staticStrings or not
        methodParsers.add(methodParser); // new methods hashset or the existed one
    }

    private boolean isEncryptMethod(String method) {
        for (String encryptPattern : MethodPattern.encMethods) {
            if (method.toLowerCase().contains(encryptPattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private boolean isEncryptClass(String clazz) {
        for (String encryptPattern : MethodPattern.encMethods) {
            if (clazz.toLowerCase().contains(encryptPattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private Body getBody(SootMethod sootMethod) {
        try {
            return sootMethod.retrieveActiveBody();
        } catch (Exception ignore) {
        }
        return null;
    }

    private void addToInitFieldsMap(MethodParser methodParser, String fieldName, Set<String> filedValues) {
        Map<String, Set<String>> initFieldsMap = initFiledsMap.computeIfAbsent(methodParser, k -> new HashMap<>());
        Set<String> fieldValues = initFieldsMap.computeIfAbsent(fieldName, k -> new HashSet<>());
        fieldValues.addAll(filedValues); // add the field values to the init fields map
    }

    public static void propagateStaticStringsFromInitStringRelatedMethod() {
        findInitStringRelatedMethods();
        for (Map.Entry<MethodParser, Set<String>> entry : initStringRelatedMethodsMap.entrySet()) {
            MethodParser methodParser = entry.getKey();
            Set<String> staticStrings = entry.getValue();
            for (MethodParser callerParser : methodParser.pre) {
                for (String str : staticStrings) {
                    propagate(callerParser, str, 3); // propagate the static string to the pre methods
                }
            }
        }
    }

    private static void propagate(MethodParser callerParser, String str, int propagateLayer) {
        if (propagateLayer <= 0) {
            return; // stop propagating if the layer is less than or equal to 0
        }
        putStaticString(str, callerParser);
        for (MethodParser preMethodParser : callerParser.pre) {
            propagate(preMethodParser, str, propagateLayer - 1); // recursively propagate to the pre method parsers
        }
    }

    private static void findInitStringRelatedMethods() {
        for (Map.Entry<MethodParser, Map<String, Set<String>>> entry : initFiledsMap.entrySet()) {
            MethodParser initMethodParser = entry.getKey();
            Map<String, Set<String>> initFields = entry.getValue();
            SootClass sootClass = initMethodParser.sootMethod.getDeclaringClass();
            for (SootMethod innerMtd : sootClass.getMethods()) {
                try {
                    Body body = innerMtd.retrieveActiveBody();
                    if (body == null) {
                        continue; // skip methods without body
                    }
                } catch (Exception ignore) {
                    continue; // skip methods without body
                }
                for (Unit u : getOrderedListOf(innerMtd, false)) {
                    if (u instanceof Stmt) {
                        try {
                            Stmt stmt = (Stmt) u;
                            for (ValueBox valueBox : stmt.getUseBoxes()) {
                                Value value = valueBox.getValue();
                                if (value instanceof FieldRef) {
                                    FieldRef fieldRef = (FieldRef) value;
                                    if (fieldRef.getField() == null) {
                                        continue; // skip if the field is null
                                    }
                                    String fieldName = fieldRef.getField().getName();
                                    // check if the field is in the init fields map
                                    if (initFields.containsKey(fieldName)) {
                                        // found a method that uses the init field
                                        MethodParser methodParser = MethodParser.getMethodParserOf(innerMtd);
                                        initStringRelatedMethodsMap.put(methodParser, initFields.get(fieldName));
                                        // add the static string to the static strings map
                                        for (String str : initFields.get(fieldName)) {
                                            putStaticString(str, methodParser);
                                        }
                                    }
                                }
                            }
                        } catch (Exception e) {
                            logger.error("Error occurred in findInitStringRelatedMethods while processing method {}: {}", innerMtd.getName(), e.toString());
                        }
                    }
                }
            }
        }
    }
}
