package com.rnkrsoft.tomcat.flowlimiter.ipdb;


import com.rnkrsoft.tomcat.flowlimiter.ipdb.exception.IPFormatException;
import org.junit.Test;

import java.io.IOException;
import java.net.URISyntaxException;

/**
 * Created by woate on 2018/12/3.
 */
public class IpDatabaseTest {

    @Test
    public void testBaseStation() throws IOException, IPFormatException, URISyntaxException {
        IpDatabase db = new IpDatabase(Thread.currentThread().getContextClassLoader().getResource("ip.ipdb").toURI());
        System.out.println(db.findBaseStation("218.201.78.116", "CN"));
    }
}