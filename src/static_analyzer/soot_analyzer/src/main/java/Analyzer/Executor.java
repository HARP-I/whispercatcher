package Analyzer;

import java.util.concurrent.*;

public class Executor {

    public static int PROCESSORS_AVAILABLE;
    private static final ExecutorService executorService;

    static {
        PROCESSORS_AVAILABLE = Runtime.getRuntime().availableProcessors();
        executorService = new ThreadPoolExecutor(
                PROCESSORS_AVAILABLE,
                PROCESSORS_AVAILABLE * 2,
                20,
                TimeUnit.HOURS,
                new LinkedBlockingQueue<>()
        );
    }

    public static CountDownLatch initLatch() {
        return new CountDownLatch(PROCESSORS_AVAILABLE);
    }

    public static void submit(Runnable runnable) {
        executorService.submit(runnable);
    }

    public static void shutDown() {
        executorService.shutdown();
    }
    public static boolean awaitTermination(long timeout, TimeUnit timeUnit) throws InterruptedException {
        return executorService.awaitTermination(timeout, timeUnit);
    }
}
