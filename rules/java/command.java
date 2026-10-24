class Command {
    void run(String host) throws Exception {
        // ruleid: openasy.java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
        // ruleid: openasy.java.command-injection
        new ProcessBuilder("sh", "-c", String.format("tar xf %s", host)).start();
        // ok: openasy.java.command-injection
        new ProcessBuilder("ping", "-c", "1", host).start();
        // ok: openasy.java.command-injection
        Runtime.getRuntime().exec("uptime");
    }
}
