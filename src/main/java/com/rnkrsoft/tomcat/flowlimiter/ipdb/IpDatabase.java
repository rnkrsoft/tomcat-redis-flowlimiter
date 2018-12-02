package com.rnkrsoft.tomcat.flowlimiter.ipdb;

import com.rnkrsoft.tomcat.flowlimiter.ipdb.exception.IPFormatException;
import com.rnkrsoft.tomcat.flowlimiter.ipdb.exception.InvalidDatabaseException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Created by woate on 2018/12/2.
 */
public class IpDatabase {
    private Reader reader;

    public IpDatabase(URI uri) throws IOException, URISyntaxException {
        this.reader = new Reader(uri);
    }

    public boolean reload(URI uri) {
        try {
            Reader r = new Reader(uri);
            this.reader = r;
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    public BaseStation findBaseStation(String addr, String language) throws IPFormatException, InvalidDatabaseException {
        String[] data = this.reader.find(addr, language);
        if (data == null) {
            return null;
        }
        return new BaseStation(this.reader.getSupportFields(), data);
    }


    public boolean isIPv4() {
        return (this.reader.getMeta().ipVersion & 0x01) == 0x01;
    }

    public boolean isIPv6() {
        return (this.reader.getMeta().ipVersion & 0x02) == 0x02;
    }

    public int buildTime() {
        return this.reader.getBuildUTCTime();
    }
}
