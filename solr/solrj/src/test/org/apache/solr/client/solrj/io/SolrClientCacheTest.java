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
package org.apache.solr.client.solrj.io;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.solr.cloud.SolrCloudTestCase;
import org.apache.solr.common.SolrException;
import org.apache.solr.common.cloud.SolrZkClient;
import org.apache.solr.common.cloud.VMParamsAllAndReadonlyDigestZkACLProvider;
import org.apache.solr.common.cloud.VMParamsSingleSetCredentialsDigestZkCredentialsProvider;
import org.apache.solr.common.util.ObjectReleaseTracker;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class SolrClientCacheTest extends SolrCloudTestCase {

  private static final Map<String, String> sysProps = new LinkedHashMap<>();
  static {
    sysProps.put(SolrZkClient.ZK_CRED_PROVIDER_CLASS_NAME_VM_PARAM_NAME,
        VMParamsSingleSetCredentialsDigestZkCredentialsProvider.class.getName());
    sysProps.put(SolrZkClient.ZK_ACL_PROVIDER_CLASS_NAME_VM_PARAM_NAME,
        VMParamsAllAndReadonlyDigestZkACLProvider.class.getName());
    sysProps.put(VMParamsSingleSetCredentialsDigestZkCredentialsProvider.DEFAULT_DIGEST_USERNAME_VM_PARAM_NAME, "admin-user");
    sysProps.put(VMParamsSingleSetCredentialsDigestZkCredentialsProvider.DEFAULT_DIGEST_PASSWORD_VM_PARAM_NAME, "pass");
    sysProps.put(VMParamsAllAndReadonlyDigestZkACLProvider.DEFAULT_DIGEST_READONLY_USERNAME_VM_PARAM_NAME, "read-user");
    sysProps.put(VMParamsAllAndReadonlyDigestZkACLProvider.DEFAULT_DIGEST_READONLY_PASSWORD_VM_PARAM_NAME, "pass");
  }

  @BeforeClass
  public static void before() throws Exception {
    sysProps.forEach(System::setProperty);
    configureCluster(1)
        .addConfig("config", getFile("solrj/solr/configsets/streaming/conf").toPath())
        .configure();
  }

  /**
   * The clear() is not tidiness, and it is not hiding a defect in the port.
   * SolrClientCache.getCloudSolrClient builds the CloudSolrClient, connects it and only then
   * stores it, so a connect that throws -- which is precisely what this fix makes happen for a
   * zkHost that is not the default -- leaves an InternalHttpClient that the cache never holds
   * and no caller can reach, and SolrTestCaseJ4's ObjectReleaseTracker then fails the whole
   * suite. That ordering is upstream's, unchanged at 8.11.3 and 9.4.1, so closing it would mean
   * writing production code upstream did not write; the test cannot close it either, because
   * the client is unreachable by the time expectThrows returns. Clearing here is what
   * SolrTestCaseJ4.teardownTestCases itself does in its finally block, one @AfterClass earlier.
   */
  @AfterClass
  public static void after() {
    sysProps.keySet().forEach(System::clearProperty);
    ObjectReleaseTracker.clear();
  }

  /**
   * The CVE probe, and the only test here that touches no method this fix adds. Nothing on the
   * 7.7.3 line calls setDefaultZKHost -- CoreContainer has no SolrClientCache at this baseline,
   * where StreamHandler owns a static one -- so a cache with no default host is what a consumer
   * actually gets, and it is the state in which the flaw bites: before the fix the cache hands
   * the local ensemble's ZooKeeper credentials to whatever host a streaming expression names.
   */
  @Test
  public void zkACLsNotUsedWhenNoDefaultZkHostIsSet() {
    SolrClientCache cache = new SolrClientCache();
    try {
      expectThrows(
          SolrException.class, () -> cache.getCloudSolrClient(zkClient().getZkServerAddress()));
    } finally {
      cache.close();
    }
  }

  @Test
  public void testZkACLsNotUsedWithDifferentZkHost() throws Exception {
    SolrClientCache cache = new SolrClientCache();
    try {
      // This ZK Host is fake, thus the ZK ACLs should not be used
      setDefaultZKHost(cache, "test:2181");
      expectThrows(
          SolrException.class, () -> cache.getCloudSolrClient(zkClient().getZkServerAddress()));
    } finally {
      cache.close();
    }
  }

  @Test
  public void testZkACLsUsedWithDifferentChroot() throws Exception {
    SolrClientCache cache = new SolrClientCache();
    try {
      // The same ZK Host is used, so the ZK ACLs should still be applied
      setDefaultZKHost(cache, zkClient().getZkServerAddress() + "/random/chroot");
      cache.getCloudSolrClient(zkClient().getZkServerAddress());
    } finally {
      cache.close();
    }
  }

  /**
   * Reflective on purpose. SolrClientCache#setDefaultZKHost ARRIVES WITH THIS FIX, and the
   * fail-before gate compiles this file against the unpatched baseline, where a direct call is a
   * compile error -- which yields no test reports at all and so proves nothing in either
   * direction. Going through reflection keeps the file compiling there, so the probe above can
   * fail for the reason it exists to detect rather than for a missing symbol.
   */
  private static void setDefaultZKHost(SolrClientCache cache, String zkHost) throws Exception {
    SolrClientCache.class.getMethod("setDefaultZKHost", String.class).invoke(cache, zkHost);
  }
}
