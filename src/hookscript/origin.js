let hookedCounter = 0; // counter of hooked methods
const enableStackInfo = false; // enable stack info or not
const DEBUG_ALL_LOADED_CLASSES = false;
const DEBUG_HOOKED_METHODS = false;
const INVOKE_TIMES_LIMIT = 40; // max record times for each method

let networkRelatedClasses = [
    "okhttp3.RealCall",
    "okhttp3.RealCall$AsyncCall",
    "com.android.okhttp.internal.huc.HttpURLConnectionImpl",
]; // special handling parameters of these classes

function sendAllLoadedClasses() {
    send(JSON.stringify({ "all_loaded_classes": { all_classes: Java.enumerateLoadedClassesSync() } }));
}

function variableToString(arg) {
    // preprocessing
    let ret = arg;
    let className = "";
    if (arg && arg.class) {
        className = arg.class.toString().replace("class ", "").replace("interface ", "");
    } else if ((arg + "").includes("@")) {
        className = (arg + "").split("@")[0];
    } else {
        return ret;
    }

    // deal with complex formats
    if (className == "android.content.Intent") {
        ret = arg.toString().replace("(has extras)", `action=${arg.getAction()}, data=${arg.getData()}, extras=${arg.getExtras()}`);
    } else if (className == "java.io.File") {
        ret = `file->{${arg.getAbsolutePath()}}`;
    } else if (className == "java.util.List") {
        let Arrays = Java.use("java.util.Arrays");
        ret = `arraylist->${Arrays.toString(arg.toArray())}`;
    } else if (className == "java.util.Map") {
        let HashMap = Java.use('java.util.HashMap');
        let newMap = HashMap.$new(arg)
        ret = variableToString(newMap);
    } else if (className == "java.util.HashMap") {
        let HashMapNode = Java.use('java.util.HashMap$Node');
        let iterator = arg.entrySet().iterator();
        ret = "hashmap->{";
        while (iterator.hasNext()) {
            let entry = Java.cast(iterator.next(), HashMapNode);
            ret += `${entry.getKey()}: ${entry.getValue()},`;
        }
        ret = ret.substring(0, ret.lastIndexOf(","));
        ret += "}";
    } else if (className == "android.app.Notification") {
        ret = arg.toString();
        if ("tickerText" in arg) {
            ret = arg.tickerText.toString();
        }
    } else if (arg instanceof Object && "toString" in arg) {
        ret = arg.toString();
    } else if (["okhttp3.Request", "com.android.okhttp.Request"].includes(className)) {
        // pass
    }
    return ret;
}


function readRequest(request, useAndroid) {
    let body = request.body();
    let raw = request.toString();
    let ret = `[NO_BODY] ${raw}`;
    let Buffer = Java.use("okio.Buffer");
    let androidBuffer = Java.use("com.android.okhttp.okio.Buffer");
    let RealBufferedSink = Java.use("okio.RealBufferedSink");
    let androidRealBufferedSink = Java.use("com.android.okhttp.okio.RealBufferedSink");
    let Okio = Java.use("okio.Okio");
    let androidOkio = Java.use("com.android.okhttp.okio.Okio");
    if (body) {
        let out = Java.use("java.io.FileOutputStream").$new("/sdcard/tmp-traffic-analysis.txt");
        let sink = (useAndroid ? androidOkio : Okio).sink(out);
        let bufferObj = (useAndroid ? androidRealBufferedSink : RealBufferedSink).$new(sink);
        body.writeTo(bufferObj);
        let buffer = readFieldViaReflection(bufferObj, "buffer");
        buffer = Java.cast(buffer, (useAndroid ? androidBuffer : Buffer));
        ret = JSON.stringify({ "raw": raw, "header": request.headers().toString(), body: buffer.readUtf8() });
    } else {
        if (Object.keys(request).includes("getBufferedRequestBody")) {
            let buffer = request.getBufferedRequestBody();
            if (buffer) {
                ret = JSON.stringify({ "raw": raw, "header": request.headers().toString(), body: buffer.readUtf8() });
            }
        }
    }
    return ret;
}

function readFieldViaReflection(targetClazz, field) {
    var clazz = Java.use("java.lang.Class");
    var castClass = Java.cast(targetClazz.getClass(), clazz);
    var field = castClass.getDeclaredField(field);
    field.setAccessible(true);
    return field.get(targetClazz);
}

function findClassFromClassLoader(className) {
    const loader = Java.enumerateClassLoadersSync().find(l => {
        try {
            return l.findClass(className);
        } catch (e) {
            return false;
        }
    });
    if (!loader) {
        return undefined;
    }
    const factory = Java.ClassFactory.get(loader);
    return factory.use(className);
}

function isJavaObjectString(str) {
    return /@[\da-fA-F]+$/.test(str);
}

function isJavaClassName(str) {
    return /^([a-zA-Z_]\w*(\.[a-zA-Z_]\w*)*\.[A-Z]\w*|int|long|short|byte|boolean|char|float|double|void)$/.test(str);
}

function isEmptyString(val) {
    return !val;
}

function isUselessArray(val) {
    return val === "arraylist->[]" || val === "[]";
}

function isUselessObject(val) {
    return val === "[object Object]" || val === "{}" || val === "hashmap->{}";
}

function isBoolean(val) {
    return /^(true|false)$/i.test(val)
}

function isNumber(val) {
    return /^\d+$/.test(val);
}

function isUseful(savedArgs, savedRet) {
    const isUsefulArgs = (savedArgs.length != 0) && savedArgs.some(arg => {
        return !isEmptyString(arg) && !isUselessArray(arg) && !isUselessObject(arg) && !isBoolean(arg) && !isNumber(arg) && !isJavaObjectString(arg) && !isJavaClassName(arg);
    });
    const isUsefulRet = !isEmptyString(savedRet) && !isUselessArray(savedRet) && !isUselessObject(savedRet) && !isBoolean(savedRet) && !isNumber(savedRet) && !isJavaObjectString(savedRet) && !isJavaClassName(savedRet);
    return isUsefulArgs || isUsefulRet;
}

function testMethod(method) {
    try {
        let clazz = Java.use(method.className);
        if (!clazz) {
            console.warn(`[!] Class ${method.className} not found, skipping...`);
            return;
        }
        let overload;
        if (method.paramsArray.length == 0) {
            overload = clazz[method.methodName].overload(); // get the method without parameters
        } else {
            overload = clazz[method.methodName].overload(...method.paramsArray); // get the overload method
        }
        if (!overload) {
            console.warn(`[!] Overload for ${method.className}.${method.methodName} not found, skipping...`);
            return;
        }
        // debug hooked methods
        if (DEBUG_HOOKED_METHODS) {
            send(JSON.stringify({ "hook_method": { class_name: method.className, method_name: method.methodName } }));
        }

        overload.implementation = function (...args) {
            if (method.invokeCnt >= INVOKE_TIMES_LIMIT) {
                return overload.apply(this, args);
            }
            console.log(`[+ ${++hookedCounter}] ${method.className}.${method.methodName}`);
            let savedArgs = [];
            for (let arg of args) {
                savedArgs.push(variableToString(arg));
            }
            if (networkRelatedClasses.includes(method.className)) {
                if (method.className.includes("okhttp3")) {
                    let request = this.request();
                    request && savedArgs.push(variableToString(request));
                } else if (method.className.includes("android.okhttp")) {
                    let httpEngineClass = Java.use("com.android.okhttp.internal.http.HttpEngine");
                    let httpEngine = Java.cast(readFieldViaReflection(this, "httpEngine"), httpEngineClass);
                    let request = httpEngine.getRequest();
                    request && savedArgs.push(variableToString(request));
                }
            }
            let stack = "";
            if (enableStackInfo) {
                stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()).toString();
            } else {
                stack = "not enabled";
            }
            // let stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()).toString();
            const ret = overload.apply(this, args); // invoke this overload method as usual
            let savedRet = variableToString(ret);
            // send(JSON.stringify({ "method_call": { time: Date.now(), class_name: method.className, method_name: method.methodName, type: type, args: savedArgs, ret: variableToString(ret), stack: stack } }));
            if (isUseful(savedArgs, savedRet) && method.invokeCnt < INVOKE_TIMES_LIMIT) {
                send(JSON.stringify({ "method_call": { api: `${method.className}.${method.methodName}`, args: savedArgs, ret: savedRet, stack: stack, time: Date.now() } }));
                method.invokeCnt++;
            }
            return ret;
        };
    } catch (e) {
        console.warn(`[!] Failed hooking ${method.className}.${method.methodName}: ${e.message}`);
    }
}

function hookMethods() {
    // debug all loaded classes
    if (DEBUG_ALL_LOADED_CLASSES) {
        sendAllLoadedClasses();
    }

    if (Java.available) {
        Java.perform(() => {
            toBeCompleted;
        });
    }
}

setImmediate(hookMethods);