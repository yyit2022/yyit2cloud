package com.yyit.cloud.uaa;

import lombok.extern.slf4j.Slf4j;
import org.hibernate.event.spi.SaveOrUpdateEvent;
import org.junit.jupiter.api.Test;

import java.util.UUID;

@Slf4j
public class HelloTests {


    @Test
    void genUUID(){
      log.info(UUID.randomUUID().toString());
    }

}
