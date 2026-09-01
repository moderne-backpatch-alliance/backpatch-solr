/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.solr.security;

import java.security.Principal;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.solr.SolrTestCaseJ4;
import org.apache.solr.common.SolrException;
import org.apache.solr.common.params.MapSolrParams;
import org.apache.solr.common.params.SolrParams;
import org.apache.solr.handler.SchemaHandler;
import org.apache.solr.handler.SolrConfigHandler;
import org.junit.Test;

/**
 * Regression tests for CVE-2026-22022: a request that a
 * {@link PermissionNameProvider} could not map to a predefined permission was
 * silently treated as "this permission does not apply", so a security.json that
 * relies on the config-read / config-edit / schema-read / security-read
 * predefined rules -- and does not also define "all" -- let the request through
 * unauthorized.
 *
 * <p>The parent 8.11.4 backpatch also covers a trailing slash on the "path"
 * parameter of /admin/zookeeper. That vector does not exist at 7.7.3:
 * ZookeeperInfoHandler does not implement PermissionNameProvider here, so the
 * predefined-permission machinery never consults it.
 */
public class TestPredefinedPermissionBypass extends SolrTestCaseJ4 {

  /**
   * An HTTP method the handler does not recognise used to yield a null
   * permission name rather than a rejection.
   */
  @Test
  public void schemaHandlerRejectsUnrecognizedHttpMethod() {
    SolrException e = expectThrows(SolrException.class, () ->
        new SchemaHandler().getPermissionName(context(new MapSolrParams(new HashMap<>()), "TRACE", "/schema", null)));
    assertEquals(SolrException.ErrorCode.BAD_REQUEST.code, e.code());
  }

  @Test
  public void solrConfigHandlerRejectsUnrecognizedHttpMethod() {
    SolrException e = expectThrows(SolrException.class, () ->
        new SolrConfigHandler().getPermissionName(context(new MapSolrParams(new HashMap<>()), "TRACE", "/config", null)));
    assertEquals(SolrException.ErrorCode.BAD_REQUEST.code, e.code());
  }

  /**
   * The bypass itself: a handler that cannot name a predefined permission must
   * not make the governing predefined rule "not apply", which is what let the
   * request fall through to the unauthenticated default.
   */
  @Test
  public void ruleBasedAuthorizationRejectsHandlerWithNoPredefinedPermission() {
    Map<String, Object> conf = new HashMap<>();
    conf.put("user-role", Collections.singletonMap("solr", "admin"));
    // security-read rather than config-read: a predefined permission's collection set
    // comes from PermissionNameProvider.Name.collName, and config-read's is "*", so
    // add2Mapping files it under mapping key "*". authorize() consults only
    // mapping.get(null) for an ADMIN request, so a config-read rule is never reached
    // on this path at all. security-read has a null collName, is filed under null, and
    // is one of the predefined rules the CVE names.
    conf.put("permissions", Collections.singletonList(mapOf("name", "security-read", "role", "admin")));

    PermissionNameProvider unmappable = ctx -> null;
    try (RuleBasedAuthorizationPlugin plugin = new RuleBasedAuthorizationPlugin()) {
      plugin.init(conf);
      expectThrows(SolrException.class, () ->
          plugin.authorize(context(new MapSolrParams(new HashMap<>()), "TRACE", "/admin/authorization", unmappable)));
    } catch (java.io.IOException e) {
      fail("unexpected IOException: " + e);
    }
  }

  private static Map<String, Object> mapOf(String k1, Object v1, String k2, Object v2) {
    Map<String, Object> m = new HashMap<>();
    m.put(k1, v1);
    m.put(k2, v2);
    return m;
  }

  private static AuthorizationContext context(SolrParams params, String httpMethod, String resource,
                                              Object handler) {
    return new AuthorizationContext() {
      @Override
      public SolrParams getParams() {
        return params;
      }

      @Override
      public Principal getUserPrincipal() {
        return null;
      }

      @Override
      public String getHttpHeader(String header) {
        return null;
      }

      @Override
      @SuppressWarnings({"rawtypes"})
      public Enumeration getHeaderNames() {
        return null;
      }

      @Override
      public String getRemoteAddr() {
        return null;
      }

      @Override
      public String getRemoteHost() {
        return null;
      }

      @Override
      public List<CollectionRequest> getCollectionRequests() {
        return Collections.emptyList();
      }

      @Override
      public RequestType getRequestType() {
        return RequestType.ADMIN;
      }

      @Override
      public String getResource() {
        return resource;
      }

      @Override
      public String getHttpMethod() {
        return httpMethod;
      }

      @Override
      public Object getHandler() {
        return handler;
      }
    };
  }
}
