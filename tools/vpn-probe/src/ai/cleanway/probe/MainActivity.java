package ai.cleanway.probe;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.ProxyInfo;
import android.net.RouteInfo;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * VPN-detection probe. Reports every signal Russian apps are known to use to
 * notice a VPN, so we can see which ones an app EXCLUDED from Cleanway's
 * tunnel (VpnService.Builder.addDisallowedApplication) still sees.
 *
 * Button press, or `am start -n <pkg>/ai.cleanway.probe.MainActivity
 * --ez auto true --es label <name>` for an unattended run. Every line goes to
 * logcat (tag CwProbe) and to getExternalFilesDir()/probe-<label>.txt.
 */
public class MainActivity extends Activity {
    static final String TAG = "CwProbe";

    /** Blocked by Cleanway's live list (2026-09-27) AND resolvable in public DNS. */
    static final String[] BLOCKED_BUT_RESOLVING = {"027xrf.com", "023trafficaccidentlawyer.com"};

    private final List<String> callbackEvents = Collections.synchronizedList(new ArrayList<String>());
    private final List<String> vpnRequestEvents = Collections.synchronizedList(new ArrayList<String>());
    private ConnectivityManager.NetworkCallback defaultCb;
    private ConnectivityManager.NetworkCallback vpnCb;
    private TextView out;
    private final Handler main = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        Button run = new Button(this);
        run.setText("Probe VPN signals");
        root.addView(run);
        out = new TextView(this);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextSize(10);
        out.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(out);
        root.addView(scroll);
        setContentView(root);

        registerCallbacks();
        run.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                probeAsync("button");
            }
        });
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        if (intent != null && intent.getBooleanExtra("auto", false)) {
            final String label = intent.getStringExtra("label") == null ? "auto" : intent.getStringExtra("label");
            // Let the network callbacks deliver their first events.
            main.postDelayed(new Runnable() {
                @Override
                public void run() {
                    probeAsync(label);
                }
            }, 1500);
        }
    }

    @Override
    protected void onDestroy() {
        ConnectivityManager cm = cm();
        try {
            if (defaultCb != null) cm.unregisterNetworkCallback(defaultCb);
            if (vpnCb != null) cm.unregisterNetworkCallback(vpnCb);
        } catch (Exception ignored) {
        }
        super.onDestroy();
    }

    private ConnectivityManager cm() {
        return (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    /** (6) What the default-network callback says, and whether a VPN-only request ever matches. */
    private void registerCallbacks() {
        ConnectivityManager cm = cm();
        defaultCb = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network n) {
                callbackEvents.add("onAvailable " + n);
            }

            @Override
            public void onCapabilitiesChanged(Network n, NetworkCapabilities nc) {
                callbackEvents.add("onCapabilitiesChanged " + n + " VPN=" + nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                        + " NOT_VPN=" + nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) + " caps=" + nc);
            }

            @Override
            public void onLinkPropertiesChanged(Network n, LinkProperties lp) {
                callbackEvents.add("onLinkPropertiesChanged " + n + " iface=" + lp.getInterfaceName() + " dns=" + lp.getDnsServers());
            }

            @Override
            public void onLost(Network n) {
                callbackEvents.add("onLost " + n);
            }
        };
        try {
            cm.registerDefaultNetworkCallback(defaultCb);
        } catch (Exception e) {
            callbackEvents.add("registerDefaultNetworkCallback failed: " + e);
        }
        vpnCb = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network n) {
                vpnRequestEvents.add("onAvailable " + n);
            }

            @Override
            public void onCapabilitiesChanged(Network n, NetworkCapabilities nc) {
                vpnRequestEvents.add("onCapabilitiesChanged " + n + " VPN=" + nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
            }

            @Override
            public void onLost(Network n) {
                vpnRequestEvents.add("onLost " + n);
            }
        };
        try {
            NetworkRequest req = new NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                    .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build();
            cm.registerNetworkCallback(req, vpnCb);
        } catch (Exception e) {
            vpnRequestEvents.add("registerNetworkCallback(VPN) failed: " + e);
        }
    }

    private void probeAsync(final String label) {
        out.setText("probing…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String report = probe(label);
                main.post(new Runnable() {
                    @Override
                    public void run() {
                        out.setText(report);
                    }
                });
            }
        }, "probe").start();
    }

    private String probe(String label) {
        List<String> r = new ArrayList<>();
        List<String> summary = new ArrayList<>();
        r.add("=== CwProbe label=" + label + " pkg=" + getPackageName()
                + " targetSdk=" + getApplicationInfo().targetSdkVersion + " sdk=" + Build.VERSION.SDK_INT
                + " at=" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date()));
        ConnectivityManager cm = cm();

        // (1) Active network capabilities — the check MAX is reported to use.
        r.add("--- [1] active network");
        boolean activeVpn = false;
        try {
            Network active = cm.getActiveNetwork();
            r.add("activeNetwork=" + active);
            NetworkCapabilities nc = active == null ? null : cm.getNetworkCapabilities(active);
            if (nc != null) {
                activeVpn = nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                r.add("hasTransport(VPN)=" + activeVpn);
                r.add("hasCapability(NOT_VPN)=" + nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN));
                if (Build.VERSION.SDK_INT >= 29) r.add("transportInfo=" + nc.getTransportInfo());
                r.add("caps=" + nc);
            } else {
                r.add("caps=null");
            }
        } catch (Exception e) {
            r.add("error " + e);
        }
        summary.add("[1] activeNetwork hasTransport(VPN): " + activeVpn);

        // (1b) Legacy NetworkInfo checks, still in old SDKs.
        boolean legacyVpn = false;
        try {
            NetworkInfo ani = cm.getActiveNetworkInfo();
            r.add("legacy activeNetworkInfo type=" + (ani == null ? "null" : ani.getType() + "/" + ani.getTypeName()));
            if (ani != null && ani.getType() == ConnectivityManager.TYPE_VPN) legacyVpn = true;
            NetworkInfo vpnInfo = cm.getNetworkInfo(ConnectivityManager.TYPE_VPN);
            r.add("legacy getNetworkInfo(TYPE_VPN)=" + (vpnInfo == null ? "null" : vpnInfo.isConnectedOrConnecting() + " " + vpnInfo));
            if (vpnInfo != null && vpnInfo.isConnectedOrConnecting()) legacyVpn = true;
            NetworkInfo[] all = cm.getAllNetworkInfo();
            StringBuilder sb = new StringBuilder();
            for (NetworkInfo ni : all) {
                sb.append(ni.getTypeName()).append('(').append(ni.getType()).append(")=").append(ni.getState()).append(' ');
                if (ni.getType() == ConnectivityManager.TYPE_VPN && ni.isConnectedOrConnecting()) legacyVpn = true;
            }
            r.add("legacy getAllNetworkInfo: " + sb);
        } catch (Exception e) {
            r.add("legacy error " + e);
        }
        summary.add("[1b] legacy NetworkInfo TYPE_VPN: " + legacyVpn);

        // (2) Every network the system lists.
        r.add("--- [2] getAllNetworks()");
        boolean anyVpn = false;
        try {
            for (Network n : cm.getAllNetworks()) {
                NetworkCapabilities nc = cm.getNetworkCapabilities(n);
                LinkProperties lp = cm.getLinkProperties(n);
                boolean vpn = nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                anyVpn |= vpn;
                r.add("net " + n + " VPN=" + vpn + " iface=" + (lp == null ? "?" : lp.getInterfaceName())
                        + " dns=" + (lp == null ? "?" : lp.getDnsServers()) + " caps=" + nc);
            }
        } catch (Exception e) {
            r.add("error " + e);
        }
        summary.add("[2] getAllNetworks() any TRANSPORT_VPN: " + anyVpn);

        // (3) Interface names.
        r.add("--- [3] NetworkInterface.getNetworkInterfaces()");
        boolean tunIface = false;
        try {
            List<NetworkInterface> ifs = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface ni : ifs) {
                StringBuilder addrs = new StringBuilder();
                for (InterfaceAddress a : ni.getInterfaceAddresses()) addrs.append(a.getAddress()).append('/').append(a.getNetworkPrefixLength()).append(' ');
                String name = ni.getName();
                boolean vpnName = looksLikeVpn(name);
                tunIface |= vpnName && ni.isUp();
                r.add("if " + name + " up=" + ni.isUp() + " p2p=" + ni.isPointToPoint() + " virtual=" + ni.isVirtual() + " addrs=" + addrs);
            }
            NetworkInterface tun0 = NetworkInterface.getByName("tun0");
            r.add("getByName(tun0)=" + (tun0 == null ? "null" : "present up=" + tun0.isUp()));
        } catch (Exception e) {
            r.add("error " + e);
        }
        summary.add("[3] NetworkInterface lists an up tun/ppp/tap: " + tunIface);

        // (4) /proc and /sys.
        r.add("--- [4] /proc/net and /sys/class/net");
        boolean procTun = false;
        for (String path : new String[]{"/proc/net/route", "/proc/net/if_inet6", "/proc/net/dev", "/proc/net/ipv6_route"}) {
            String body = readFile(path);
            boolean mentions = body != null && containsVpnName(body);
            procTun |= mentions;
            r.add(path + " readable=" + (body != null) + " mentionsTun=" + mentions);
            if (body != null) {
                for (String line : body.split("\n")) r.add("  " + line);
            }
        }
        String[] sys = new File("/sys/class/net").list();
        boolean sysTun = false;
        if (sys != null) {
            for (String s : sys) sysTun |= looksLikeVpn(s);
        }
        r.add("/sys/class/net list=" + (sys == null ? "unreadable" : java.util.Arrays.toString(sys)));
        summary.add("[4] /proc/net/* mentions tun: " + procTun + "; /sys/class/net has tun: " + sysTun);

        // (5) DNS: system properties and LinkProperties.
        r.add("--- [5] DNS");
        String reflDns = systemProperty("net.dns1");
        r.add("SystemProperties.get(net.dns1) via reflection=" + reflDns);
        r.add("getprop net.dns1=" + exec("getprop net.dns1") + " net.dns2=" + exec("getprop net.dns2"));
        boolean dnsTunnel = false;
        try {
            Network active = cm.getActiveNetwork();
            LinkProperties lp = active == null ? null : cm.getLinkProperties(active);
            if (lp != null) {
                r.add("active iface=" + lp.getInterfaceName() + " dns=" + lp.getDnsServers()
                        + (Build.VERSION.SDK_INT >= 28 ? " privateDnsActive=" + lp.isPrivateDnsActive() + " privateDnsServer=" + lp.getPrivateDnsServerName() : ""));
                for (RouteInfo ri : lp.getRoutes()) r.add("  route " + ri);
                for (InetAddress a : lp.getDnsServers()) {
                    if ("10.0.0.1".equals(a.getHostAddress())) dnsTunnel = true;
                }
                if (lp.getInterfaceName() != null && looksLikeVpn(lp.getInterfaceName())) dnsTunnel = true;
            } else {
                r.add("active LinkProperties=null");
            }
            ProxyInfo proxy = cm.getDefaultProxy();
            r.add("defaultProxy=" + proxy + " http.proxyHost=" + System.getProperty("http.proxyHost"));
        } catch (Exception e) {
            r.add("error " + e);
        }
        summary.add("[5] active LinkProperties DNS/iface is the tunnel (10.0.0.1 / tun): " + dnsTunnel + "; net.dns1='" + reflDns + "'");

        // (6) Callbacks.
        r.add("--- [6] default network callback events");
        boolean cbVpn = false;
        synchronized (callbackEvents) {
            for (String ev : callbackEvents) {
                r.add("  " + ev);
                if (ev.contains(" VPN=true")) cbVpn = true;
            }
        }
        r.add("--- [6b] VPN-only NetworkRequest callback events");
        boolean reqVpn;
        synchronized (vpnRequestEvents) {
            for (String ev : vpnRequestEvents) r.add("  " + ev);
            reqVpn = false;
            for (String ev : vpnRequestEvents) if (ev.startsWith("onAvailable")) reqVpn = true;
        }
        summary.add("[6] default-network callback reported VPN: " + cbVpn + "; VPN-only request matched: " + reqVpn);

        // (7) Traffic: does the probe's own DNS/HTTP go through the shield?
        r.add("--- [7] DNS + HTTP from this app");
        boolean blockedResolved = false;
        for (String host : BLOCKED_BUT_RESOLVING) {
            String res = resolve(host);
            r.add("resolve " + host + " -> " + res);
            if (!res.startsWith("FAIL")) blockedResolved = true;
        }
        r.add("resolve example.com -> " + resolve("example.com"));
        String http1 = http("https://connectivitycheck.gstatic.com/generate_204");
        String http2 = http("https://example.com/");
        r.add("GET generate_204 -> " + http1);
        r.add("GET https://example.com/ -> " + http2);
        summary.add("[7] Cleanway-blocked names resolve for this app (tunnel bypassed): " + blockedResolved
                + "; HTTP generate_204: " + http1 + "; example.com: " + http2);

        // (8) Installed VPN apps: any app can list them with a <queries> entry
        // for the android.net.VpnService intent — no QUERY_ALL_PACKAGES needed.
        r.add("--- [8] installed apps declaring android.net.VpnService");
        List<String> vpnApps = new ArrayList<>();
        try {
            for (android.content.pm.ResolveInfo ri : getPackageManager().queryIntentServices(
                    new Intent("android.net.VpnService"), 0)) {
                vpnApps.add(ri.serviceInfo.packageName + "/" + ri.serviceInfo.name);
            }
        } catch (Exception e) {
            r.add("error " + e);
        }
        r.add("vpnServices=" + vpnApps);
        summary.add("[8] installed VPN apps visible via <queries>: " + vpnApps);

        r.add("--- SUMMARY");
        r.addAll(summary);

        StringBuilder all = new StringBuilder();
        for (String line : r) {
            Log.i(TAG, line.length() > 3500 ? line.substring(0, 3500) + "…" : line);
            all.append(line).append('\n');
        }
        writeReport(label, all.toString());
        Log.i(TAG, "=== done label=" + label);
        return all.toString();
    }

    private static boolean looksLikeVpn(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        return n.startsWith("tun") || n.startsWith("ppp") || n.startsWith("tap") || n.startsWith("ipsec") || n.startsWith("wg");
    }

    private static boolean containsVpnName(String body) {
        for (String line : body.split("\n")) {
            for (String tok : line.trim().split("[\\s:]+")) {
                if (!tok.isEmpty() && looksLikeVpn(tok)) return true;
            }
        }
        return false;
    }

    private static String readFile(String path) {
        try (BufferedReader br = new BufferedReader(new FileReader(path))) {
            StringBuilder sb = new StringBuilder();
            String line;
            int n = 0;
            while ((line = br.readLine()) != null && n++ < 60) sb.append(line).append('\n');
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static String systemProperty(String key) {
        try {
            Class<?> c = Class.forName("android.os.SystemProperties");
            return String.valueOf(c.getMethod("get", String.class).invoke(null, key));
        } catch (Throwable t) {
            return "blocked: " + t.getClass().getSimpleName();
        }
    }

    private static String exec(String cmd) {
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = br.readLine();
            p.waitFor();
            return "'" + (line == null ? "" : line) + "'";
        } catch (Exception e) {
            return "error " + e.getClass().getSimpleName();
        }
    }

    private static String resolve(String host) {
        long t0 = System.currentTimeMillis();
        try {
            InetAddress[] a = InetAddress.getAllByName(host);
            return a[0].getHostAddress() + " (" + (System.currentTimeMillis() - t0) + " ms)";
        } catch (Exception e) {
            return "FAIL " + e.getClass().getSimpleName() + " (" + (System.currentTimeMillis() - t0) + " ms)";
        }
    }

    private static String http(String url) {
        long t0 = System.currentTimeMillis();
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(8000);
            c.setReadTimeout(8000);
            int code = c.getResponseCode();
            return "HTTP " + code + " (" + (System.currentTimeMillis() - t0) + " ms)";
        } catch (Exception e) {
            return "FAIL " + e.getClass().getSimpleName() + " (" + (System.currentTimeMillis() - t0) + " ms)";
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private void writeReport(String label, String body) {
        try {
            File dir = getExternalFilesDir(null);
            if (dir == null) return;
            try (FileOutputStream fo = new FileOutputStream(new File(dir, "probe-" + label + ".txt"))) {
                fo.write(body.getBytes("UTF-8"));
            }
        } catch (Exception e) {
            Log.w(TAG, "write failed " + e);
        }
    }
}
