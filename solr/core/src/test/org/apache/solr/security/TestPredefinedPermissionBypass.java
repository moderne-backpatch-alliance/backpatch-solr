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
import org.apache.solr.handler.admin.ZookeeperInfoHandler;
import org.junit.Test;

/**
 * Regression tests for CVE-2026-22022: a request that a
 * {@link PermissionNameProvider} could not map to a predefined permission was
 * silently treated as "this permission does not apply", so a security.json that
 * relies on the config-read / config-edit / schema-read / security-read
 * predefined rules -- and does not also define "all" -- let the request through
 * unauthorized.
 */
public class TestPredefinedPermissionBypass extends SolrTestCaseJ4 {

  /**
   * A trailing slash on the "path" parameter used to steer /admin/zookeeper away
   * from SECURITY_READ_PERM and onto the much more widely granted ZK_READ_PERM,
   * while ZooKeeper itself still served /security.json.
   */
  @Test
  public void zookeeperInfoHandlerNormalizesTrailingSlashOnSecurityJson() {
    ZookeeperInfoHandler handler = new ZookeeperInfoHandler(null);
    Map<String, String> params = new HashMap<>();
    params.put("path", "/security.json/");
    params.put("detail", "true");

    assertEquals(PermissionNameProvider.Name.SECURITY_READ_PERM,
        handler.getPermissionName(context(new MapSolrParams(params), "GET", "/admin/zookeeper", null)));
  }

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
    conf.put("permissions", Collections.singletonList(mapOf("name", "config-read", "role", "admin")));

    PermissionNameProvider unmappable = ctx -> null;
    try (RuleBasedAuthorizationPlugin plugin = new RuleBasedAuthorizationPlugin()) {
      plugin.init(conf);
      expectThrows(SolrException.class, () ->
          plugin.authorize(context(new MapSolrParams(new HashMap<>()), "TRACE", "/config", unmappable)));
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
