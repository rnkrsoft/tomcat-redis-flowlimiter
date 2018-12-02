package com.rnkrsoft.tomcat.flowlimiter;

import com.rnkrsoft.tomcat.flowlimiter.ipdb.BaseStation;
import com.rnkrsoft.tomcat.flowlimiter.ipdb.IpDatabase;
import lombok.Data;
import org.apache.catalina.Globals;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.Protocol;
import redis.clients.util.Pool;

import javax.servlet.ServletException;
import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * Created by liucheng on 2018/12/3.
 * Redis流量限制
 */
@Data
public class RedisFlowLimiterHandlerValve extends ValveBase {
    private static final Log log = LogFactory.getLog(RedisFlowLimiterHandlerValve.class);
    public static final String DENY = "deny";
    public static final String ALLOW = "allow";
    //===========================日志文件=================================
    /**
     * 时间戳
     */
    private volatile String dateStamp = "";
    /**
     * 日志前缀
     */
    protected String prefix = "ip_access.";
    /**
     * The suffix that is added to log file filenames.
     */
    protected String suffix = "";
    /**
     * 日志存放路径
     */
    private String directory = "logs";
    /**
     * Should we rotate our log file? Default is true (like old behavior)
     */
    protected boolean rotatable = true;
    /**
     * The PrintWriter to which we are currently logging, if any.
     */
    protected PrintWriter writer = null;
    /**
     * The current log file we are writing to. Helpful when checkExists
     * is true.
     */
    protected File currentLogFile = null;
    /**
     * Instant when the log daily rotation was last checked.
     */
    private volatile long rotationLastChecked = 0L;

    private String dataFormat = "yyyyMMdd";

    private SimpleDateFormat fileDateFormatter;

    //==============================redis=================================
    protected String host = "localhost";
    protected int port = 6379;
    protected int database = 0;
    protected String password = null;
    protected int timeout = Protocol.DEFAULT_TIMEOUT;
    protected Pool<Jedis> connectionPool;
    protected JedisPoolConfig connectionPoolConfig = new JedisPoolConfig();
    //==============================限流=================================

    private IpDatabase ipDatabase;
    private SimpleDateFormat limitDataFormatter;

    private String limitDateFormat = "yyyyMMddhhmm";

    private int maxThresholdPreMin = 30;

    private String ipdbFileName = "ip.ipdb";

    private String iptablesFileName = "iptables.properties";

    private String strictCheckIp = "false";

    private String allowProvinces = "";
    /**
     * 是否显示拒绝日志
     */
    private String showDenyLog = "false";

    private Set<String> allowProvincesSet = new HashSet();

    private SimpleDateFormat currentDataFormatter = new SimpleDateFormat("yyyy/MM/dd hh:mm:ss.SSS");

    private final Properties iptables = new Properties();


    @Override
    protected void initInternal() throws LifecycleException {
        super.initInternal();
        this.connectionPool = new JedisPool(this.connectionPoolConfig, getHost(), getPort(), getTimeout(), getPassword());
        if (fileDateFormatter == null) {
            this.fileDateFormatter = new SimpleDateFormat(this.dataFormat);
        }
        if (limitDataFormatter == null) {
            this.limitDataFormatter = new SimpleDateFormat(limitDateFormat);
        }
        File dir = new File("conf");
        if (!dir.isAbsolute()) {
            dir = new File(System.getProperty(Globals.CATALINA_BASE_PROP), "conf");
        }
        if (!dir.mkdirs() && !dir.isDirectory()) {
            log.error(MessageFormatter.format("tomcat conf dir is not exists!"));
        }
        try {
            File ipdbFile = new File(dir, ipdbFileName);
            if (ipdbFile.exists()) {
                this.ipDatabase = new IpDatabase(ipdbFile.toURI());
            } else {
                log.error(MessageFormatter.format("please check ipdb file is '{}'?", ipdbFile.getAbsolutePath()));
            }
        } catch (IOException e) {           log(MessageFormatter.format("please ipdb file is exists!"));
        } catch (URISyntaxException e) {
            log(MessageFormatter.format("please ipdb file is exists!"));
        }
        this.allowProvincesSet.clear();
        String[] allowProvinces0 = allowProvinces.split(";");
        for (String allowProvince : allowProvinces0) {
            this.allowProvincesSet.add(allowProvince.trim());
        }
        InputStream iptableInputStream = null;
        try {
            File iptablesFile = new File(dir, iptablesFileName);
            if (iptablesFile.exists()) {
                iptableInputStream = new FileInputStream(iptablesFile);
                iptables.load(iptableInputStream);
            } else {
                log.error(MessageFormatter.format("please check iptables file is '{}'?", iptablesFile.getAbsolutePath()));
                iptablesFile.createNewFile();
            }
        } catch (IOException e) {
            //nothing
        } finally {
            if (iptableInputStream != null) {
                try {
                    iptableInputStream.close();
                } catch (IOException e) {
                    //nothing
                }
            }
        }

    }

    @Override
    protected synchronized void stopInternal() throws LifecycleException {
        super.stopInternal();
        this.connectionPool.destroy();
    }

    protected Jedis acquireConnection() {
        Jedis jedis = connectionPool.getResource();
        if (getDatabase() != 0) {
            jedis.select(getDatabase());
        }
        return jedis;
    }

    protected void returnConnection(Jedis jedis, Boolean error) {
        if (error) {
            connectionPool.returnBrokenResource(jedis);
        } else {
            connectionPool.returnResource(jedis);
        }
    }

    protected void returnConnection(Jedis jedis) {
        returnConnection(jedis, false);
    }

    /**
     * Open the new log file for the date specified by <code>dateStamp</code>.
     */
    protected synchronized void open() {
        // Create the directory if necessary
        File dir = new File(directory);
        if (!dir.isAbsolute()) {
            dir = new File(System.getProperty(Globals.CATALINA_BASE_PROP), directory);
        }
        if (!dir.mkdirs() && !dir.isDirectory()) {
            log.error(sm.getString("flowlimit.openDirFail", dir));
        }

        // Open the current log file
        File pathname;
        // If no rotate - no need for dateStamp in fileName
        if (rotatable) {
            pathname = new File(dir.getAbsoluteFile(), prefix + dateStamp + suffix);
        } else {
            pathname = new File(dir.getAbsoluteFile(), prefix + suffix);
        }
        File parent = pathname.getParentFile();
        if (!parent.mkdirs() && !parent.isDirectory()) {
            log.error(sm.getString("flowlimit.openDirFail", parent));
        }

        Charset charset = null;
        if (charset == null) {
            charset = Charset.defaultCharset();
        }
        try {
            writer = new PrintWriter(new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(pathname, true), charset), 128000),
                    false);

            currentLogFile = pathname;
        } catch (IOException e) {
            writer = null;
            log.error("flowLimit.openFail");
            currentLogFile = null;
        }
    }

    /**
     * Close the currently open log file (if any)
     */
    private synchronized void close() {
        if (writer == null) {
            return;
        }
        writer.flush();
        writer.close();
        writer = null;
        currentLogFile = null;
    }

    /**
     * Log the specified message to the log file, switching files if the date
     * has changed since the previous log call.
     *
     * @param format Message to be logged
     * @param args arges
     */
    public void log(final String format, final Object... args) {
        long systime = System.currentTimeMillis();
        if ((systime - rotationLastChecked) > 1000) {
            synchronized (this) {
                if ((systime - rotationLastChecked) > 1000) {
                    rotationLastChecked = systime;
                    String tsDate;
                    // Check for a change of date
                    tsDate = fileDateFormatter.format(new Date(systime));
                    // If the date has changed, switch log files
                    if (!dateStamp.equals(tsDate)) {
                        close();
                        dateStamp = tsDate;
                        open();
                    }
                }
            }
        }
        /* In case something external rotated the file instead */
        synchronized (this) {
            if (currentLogFile != null && !currentLogFile.exists()) {
                try {
                    close();
                } catch (Throwable e) {
                    log.info(sm.getString("flowlimit.closeFail"), e);
                }
                /* Make sure date is correct */
                dateStamp = fileDateFormatter.format(new Date(System.currentTimeMillis()));
                open();
            }
        }

        // Log this message
        synchronized (this) {
            if (writer != null) {
                writer.println(MessageFormatter.format(format, args));
                writer.flush();
            }
        }
    }

    /**
     * 将一个IP添加到黑名单中
     * @param clientIp IP
     */
    synchronized void addBlacklist(String clientIp){
        File dir = new File("conf");
        if (!dir.isAbsolute()) {
            dir = new File(System.getProperty(Globals.CATALINA_BASE_PROP), "conf");
        }
        if (!dir.mkdirs() && !dir.isDirectory()) {
            log.error(MessageFormatter.format("tomcat conf dir is not exists!"));
        }
        this.iptables.put(clientIp, DENY);
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(new File(dir, iptablesFileName));
            this.iptables.store(fos, "iptables");
        } catch (FileNotFoundException e) {
            //nothing
        } catch (IOException e) {
            //nothing
        } finally {
            if (fos != null){
                try {
                    fos.close();
                } catch (IOException e) {
                    //nothing
                }
            }
        }
    }
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        //获取客户端真实IP地址
        String clientIp = NetworkUtils.getClientIp(request);
        Jedis jedis = null;
        try {
            String value = iptables.getProperty(clientIp);
            if (DENY.equals(value)) {
                if ("true".equalsIgnoreCase(showDenyLog)) {
                    log("{}, {}, cause deny in blacklist", currentDataFormatter.format(new Date()), clientIp);
                }
                response.setStatus(200);
                return;
            }
            jedis = acquireConnection();
            String key = clientIp + ":" + this.limitDataFormatter.format(new Date());
            long limit = jedis.incr(key);
            if (limit == 1) {
                //设置为2分钟过期
                jedis.expire(key, 2 * 60);
            }

            if (limit < this.maxThresholdPreMin) {
                //未超过流量的，则放行
            }else if (limit > this.maxThresholdPreMin && limit < 2 * this.maxThresholdPreMin && !ALLOW.equals(value)){//流量未阈值的已被至两倍之间，也不属于白名单中的，则直接返回
                log("{}, {}, cause limit deny {}", currentDataFormatter.format(new Date()), clientIp, limit);
                response.setStatus(200);
                return;
            }else if (!ALLOW.equals(value)){//流量超过了阈值的两倍，也不属于白名单中的，则自动添加黑名单
                log("{}, {}, cause limit deny {} auto add blacklist ", currentDataFormatter.format(new Date()), clientIp, limit);
                //自动添加到黑名单中
                addBlacklist(clientIp);
                response.setStatus(200);
                return;
            }else{
                //超过流量，但是为白名单
            }
            //检查源地址所属省，不为允许的则直接拒绝
            if (ipDatabase != null) {
                try {
                    BaseStation baseStation = ipDatabase.findBaseStation(clientIp, "CN");
                    if (!allowProvincesSet.isEmpty() && !allowProvincesSet.contains(baseStation.getRegionName().trim())) {
                        log("{}, {} , cause '{}' is deny access!", currentDataFormatter.format(new Date()), clientIp, baseStation.getRegionName());
                        response.setStatus(200);
                        return;
                    }
                } catch (Exception e) {
                    if (Boolean.parseBoolean(strictCheckIp)) {
                        log("{}, {} , cause ip illegal and enabled strict check ip!", currentDataFormatter.format(new Date()), clientIp);
                        response.setStatus(200);
                        return;
                    }
                }
            }
        } finally {
            if (jedis != null) {
                returnConnection(jedis);
            }
        }
        getNext().invoke(request, response);
    }
}
