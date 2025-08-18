import type { Pod } from 'kubernetes-types/core/v1';

import { Crypto } from '../js/kubewarden/host_capabilities/crypto/crypto';
import type { Certificate } from '../js/kubewarden/host_capabilities/crypto/types';
import { Kubernetes } from '../js/kubewarden/host_capabilities/kubernetes/kubernetes';
import type { CanIRequest } from '../js/kubewarden/host_capabilities/kubernetes/types';
import { Network } from '../js/kubewarden/host_capabilities/net/network';
import { Manifest } from '../js/kubewarden/host_capabilities/oci/manifest/manifest';
import { ManifestConfig } from '../js/kubewarden/host_capabilities/oci/manifest_config/manifest_config';
import { ManifestDigest } from '../js/kubewarden/host_capabilities/oci/manifest_digest/manifest_digest';
import { Validation } from '../js/kubewarden/validation';

import type { PolicySettings } from './policy_settings';

/**
 * Handles OCI manifest digest lookup success scenario
 */
export function handleOciManifestDigestSuccess(): Validation.ValidationResponse {
  const image = 'docker.io/library/busybox:1.36';
  const digest = ManifestDigest.getOCIManifestDigest(image);
  return new Validation.ValidationResponse(
    !!digest,
    digest ? undefined : 'Failed to retrieve OCI manifest digest',
    undefined,
    undefined,
    { digest: digest || '' },
  );
}

/**
 * Handles OCI manifest digest lookup failure scenario
 */
export function handleOciManifestDigestFailure(): Validation.ValidationResponse {
  const image = 'registry.testing.lan/nonexistent-image:1.0.0';
  const digest = ManifestDigest.getOCIManifestDigest(image); //host call should fail
  return new Validation.ValidationResponse(
    !digest,
    `Unexpectedly succeeded in manifest digest lookup`,
    undefined,
    undefined,
    { digest: digest || '' },
  );
}

/**
 * Handles DNS lookup success scenario
 */
export function handleDnsLookupSuccess(): Validation.ValidationResponse {
  const ips = Network.dnsLookup('google.com').ips;
  return new Validation.ValidationResponse(
    !!ips && ips.length > 0,
    ips && ips.length > 0 ? undefined : 'Failed to retrieve DNS lookup IPs',
    undefined,
    undefined,
    { ips: ips.join(', ') || '' },
  );
}

/**
 * Handles DNS lookup failure scenario
 */
export function handleDnsLookupFailure(): Validation.ValidationResponse {
  const ips = Network.dnsLookup('invalid.nonexistent.tld').ips; // host call should fail
  return new Validation.ValidationResponse(
    false,
    'Unexpectedly retrieved DNS lookup IPs',
    undefined,
    undefined,
    { ips: ips.join(', ') },
  );
}

/**
 * Handles OCI manifest lookup success scenario
 */
export function handleOciManifestSuccess(): Validation.ValidationResponse {
  const image = 'docker.io/library/busybox:1.36';
  const manifest = Manifest.getOCIManifest(image);
  return new Validation.ValidationResponse(
    !!manifest,
    manifest ? undefined : 'Failed to retrieve OCI manifest',
    undefined,
    undefined,
    { manifest: manifest ? JSON.stringify(manifest) : '' },
  );
}

/**
 * Handles OCI manifest lookup failure scenario
 */
export function handleOciManifestFailure(): Validation.ValidationResponse {
  const image = 'example.test/nonexistent-image:1.0.0';
  const manifest = Manifest.getOCIManifest(image);
  return new Validation.ValidationResponse(
    !manifest,
    `Unexpectedly succeeded in manifest lookup`,
    undefined,
    undefined,
    { manifest: '' },
  );
}

/**
 * Handles the default privileged container validation
 */
export function handlePrivilegedContainerValidation(
  validationRequest: any,
  settings: PolicySettings,
): Validation.ValidationResponse {
  if (settings.ignoredNamespaces?.includes(validationRequest.request.namespace || '')) {
    console.error('Privileged containers are allowed inside of ignored namespace');
    return Validation.acceptRequest();
  }

  const pod = JSON.parse(JSON.stringify(validationRequest.request.object)) as Pod;
  const privileged =
    pod.spec?.containers?.some(container => container.securityContext?.privileged) || false;
  if (privileged) {
    return Validation.rejectRequest('privileged containers are not allowed');
  }
  return Validation.acceptRequest();
}

/**
 * Handles OCI manifest and config lookup success scenario
 */
export function handleOciManifestAndConfigSuccess(): Validation.ValidationResponse {
  const image = 'docker.io/library/busybox:1.36';
  const response = ManifestConfig.getOCIManifestAndConfig(image);
  return new Validation.ValidationResponse(
    !!response.manifest && !!response.config,
    response.manifest && response.config ? undefined : 'Failed to retrieve OCI manifest and config',
    undefined,
    undefined,
    {
      manifest: response.manifest ? JSON.stringify(response.manifest) : '',
      digest: response.digest || '',
      config: response.config ? JSON.stringify(response.config) : '',
    },
  );
}

/**
 * Handles OCI manifest and config lookup failure scenario
 */
export function handleOciManifestAndConfigFailure(): Validation.ValidationResponse {
  const image = 'example.test/nonexistent-image';
  const response = ManifestConfig.getOCIManifestAndConfig(image); // host call should fail
  return new Validation.ValidationResponse(
    !response.manifest && !response.config,
    `Unexpectedly succeeded in manifest and config lookup`,
    undefined,
    undefined,
    {
      manifest: response.manifest ? JSON.stringify(response.manifest) : '',
      digest: response.digest || '',
      config: response.config ? JSON.stringify(response.config) : '',
    },
  );
}

/**
 * Handles get resource success scenario
 */
export function handleGetResourceSuccess(): Validation.ValidationResponse {
  const ns = Kubernetes.getResource({
    api_version: 'v1',
    kind: 'Namespace',
    name: 'test-policy',
    disable_cache: false,
  });

  if (ns?.metadata?.labels?.['demo-namespace'] === 'true') {
    return Validation.acceptRequest();
  }

  return Validation.rejectRequest('Namespace does not have label demo-namespace=true');
}

/**
 * Handles get resource failure scenario
 */
export function handleGetResourceFailure(): Validation.ValidationResponse {
  Kubernetes.getResource({
    api_version: 'v1',
    kind: 'Namespace',
    name: 'test-policy',
    disable_cache: false,
  });

  return Validation.rejectRequest('Unexpectedly succeeded in getResource');
}

/**
 * Handles list all resources success scenario
 */
export function handleListAllResourcesSuccess(): Validation.ValidationResponse {
  const pods = Kubernetes.listAllResources({
    api_version: 'v1',
    kind: 'Pod',
    label_selector: 'app=nginx',
  });

  const podCount = pods.items?.length || 0;
  return new Validation.ValidationResponse(
    podCount > 0,
    podCount > 0 ? undefined : 'Failed to retrieve pods',
    undefined,
    undefined,
    { podCount: podCount.toString(), pods: JSON.stringify(pods) },
  );
}

/**
 * Handles list all resources failure scenario
 */
export function handleListAllResourcesFailure(): Validation.ValidationResponse {
  const pods = Kubernetes.listAllResources({
    api_version: 'v1',
    kind: 'InvalidResource',
  }); // host call should fail

  return new Validation.ValidationResponse(
    false,
    'Unexpectedly succeeded in listAllResources',
    undefined,
    undefined,
    { pods: JSON.stringify(pods) },
  );
}

/**
 * Handles list resources by namespace success scenario
 */
export function handleListResourcesByNamespaceSuccess(): Validation.ValidationResponse {
  const configMaps = Kubernetes.listResourcesByNamespace({
    api_version: 'v1',
    kind: 'ConfigMap',
    namespace: 'kube-system',
    label_selector: 'component=kube-proxy',
  });

  const configMapCount = configMaps?.items?.length || 0;
  return new Validation.ValidationResponse(
    configMapCount > 0,
    configMapCount > 0 ? undefined : 'Failed to retrieve configmaps',
    undefined,
    undefined,
    {
      configMapCount: configMapCount.toString(),
      configMaps: JSON.stringify(configMaps),
    },
  );
}

/**
 * Handles list resources by namespace failure scenario
 */
export function handleListResourcesByNamespaceFailure(): Validation.ValidationResponse {
  const resources = Kubernetes.listResourcesByNamespace({
    api_version: 'v1',
    kind: 'Pod',
    namespace: 'nonexistent-namespace',
  }); // host call should fail

  return new Validation.ValidationResponse(
    false,
    'Unexpectedly succeeded in listResourcesByNamespace',
    undefined,
    undefined,
    { resources: JSON.stringify(resources) },
  );
}

/**
 * Handles canI success scenario - checking if we can create pods in default namespace
 */
export function handleCanISuccess(): Validation.ValidationResponse {
  const review: CanIRequest = {
    subject_access_review: {
      groups: undefined,
      resource_attributes: {
        namespace: undefined,
        verb: 'create',
        group: '',
        resource: 'pods',
      },
      user: 'system:serviceaccount:default:my-service-account',
    },
    disable_cache: false,
  };

  const result = Kubernetes.canI(review);
  return new Validation.ValidationResponse(result.allowed, result.reason);
}

/**
 * Handles canI failure scenario - checking if we can delete cluster-scoped resources
 */
export function handleCanIFailure(): Validation.ValidationResponse {
  const canIResponse = Kubernetes.canI({
    subject_access_review: {
      groups: [],
      resource_attributes: {
        namespace: '',
        verb: 'delete',
        group: '',
        resource: 'nodes',
      },
      user: 'system:serviceaccount:kubewarden:kubewarden-controller',
    },
    disable_cache: false,
  }); // host call should return denied

  return new Validation.ValidationResponse(
    canIResponse.allowed === false,
    canIResponse.allowed === false ? undefined : 'Unexpectedly allowed forbidden action',
    undefined,
    undefined,
    {
      allowed: canIResponse.allowed?.toString() || 'false',
      reason: canIResponse.reason || '',
      evaluationError: canIResponse.evaluationError || '',
    },
  );
}

/**
 * Handles crypto certificate verification with a real valid certificate
 */
export function handleCryptoVerifyCertSuccess(): Validation.ValidationResponse {
  // Real certificate generated with OpenSSL
  const certDer = [
    0x30, 0x82, 0x02, 0x9e, 0x30, 0x82, 0x01, 0x86, 0x02, 0x09, 0x00, 0xc3, 0xd0, 0x58, 0x59, 0x6a,
    0x78, 0x30, 0xd3, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x54,
    0x65, 0x73, 0x74, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x38, 0x31, 0x38, 0x30,
    0x39, 0x30, 0x30, 0x31, 0x31, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x38, 0x31, 0x38, 0x30, 0x39,
    0x30, 0x30, 0x31, 0x31, 0x5a, 0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x06, 0x54, 0x65, 0x73, 0x74, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc3, 0x36, 0x73, 0x69, 0x69, 0xb2, 0x44,
    0x11, 0xb0, 0xd1, 0x25, 0x76, 0x6a, 0xfe, 0x06, 0x2f, 0x02, 0x82, 0xad, 0x65, 0x6e, 0x0a, 0x1e,
    0xb8, 0xaf, 0x2c, 0x30, 0x43, 0xd4, 0x54, 0x7a, 0xe0, 0x6f, 0x78, 0xc7, 0xc3, 0x5a, 0xeb, 0x72,
    0x02, 0x21, 0x76, 0xe9, 0x77, 0x07, 0x6e, 0xdb, 0x4c, 0x25, 0x33, 0xbc, 0x38, 0x1e, 0xd7, 0x39,
    0x50, 0x36, 0x31, 0x26, 0x16, 0xac, 0x7d, 0x07, 0xed, 0xe7, 0x06, 0x86, 0x63, 0x92, 0x5a, 0x8c,
    0xee, 0x65, 0x5a, 0x10, 0xad, 0x0a, 0x55, 0x79, 0x1d, 0x44, 0xaa, 0x51, 0x34, 0x7f, 0xd8, 0x73,
    0x8a, 0x1a, 0x78, 0x82, 0x2d, 0xb6, 0x7e, 0x6f, 0xfc, 0x61, 0x08, 0x9f, 0xd4, 0x26, 0xf9, 0x99,
    0x24, 0x98, 0x4c, 0x26, 0x56, 0x83, 0xd0, 0x05, 0x5e, 0x64, 0x90, 0xa3, 0x5b, 0x49, 0xbd, 0x0a,
    0x30, 0x7d, 0xbc, 0xe0, 0x1a, 0x9a, 0xf2, 0xf9, 0xc0, 0x09, 0x3c, 0xdd, 0x16, 0xbc, 0xc9, 0x40,
    0x36, 0xdd, 0x25, 0x82, 0x35, 0x9e, 0x27, 0x84, 0x84, 0x89, 0x04, 0x39, 0x0d, 0xcc, 0xaa, 0x72,
    0xe9, 0x98, 0x26, 0xda, 0xe5, 0x99, 0xd9, 0x30, 0x44, 0xd5, 0xaa, 0xd1, 0xbb, 0xe4, 0xa0, 0xdb,
    0x62, 0x3b, 0xb4, 0x86, 0x6c, 0x6b, 0x63, 0x60, 0xa5, 0xce, 0xcf, 0x7c, 0x70, 0xdb, 0x9e, 0xff,
    0x6a, 0x7e, 0xd4, 0x35, 0x58, 0xa2, 0x24, 0x12, 0x9d, 0x8a, 0xaf, 0xfb, 0xe5, 0xd9, 0xb7, 0x8f,
    0xbe, 0x14, 0xa9, 0xfa, 0x32, 0xcc, 0x66, 0xeb, 0xf5, 0xc7, 0x23, 0x48, 0x96, 0x1e, 0xc8, 0x3f,
    0xb1, 0x22, 0xdd, 0x96, 0x5f, 0x9a, 0xb7, 0x79, 0xc1, 0xe4, 0x9d, 0x82, 0x7c, 0xff, 0x10, 0x8a,
    0x2c, 0xa4, 0x2b, 0x9c, 0x91, 0xd2, 0xde, 0x63, 0xc4, 0xb4, 0xb0, 0xa8, 0x26, 0x8f, 0x21, 0x57,
    0x83, 0x5b, 0x04, 0xe9, 0x0d, 0xa3, 0xc2, 0x4e, 0xe5, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01,
    0x01, 0x00, 0x6d, 0x96, 0xd9, 0xdf, 0xa9, 0x1c, 0x5d, 0xe2, 0x4c, 0x68, 0x21, 0xe5, 0x37, 0xe8,
    0x7e, 0x89, 0xe1, 0x1d, 0x2e, 0x25, 0xea, 0xfe, 0x75, 0x06, 0x28, 0x3c, 0x22, 0xcc, 0xc8, 0xc9,
    0x25, 0x8b, 0xc0, 0xa2, 0x99, 0x56, 0x39, 0xc9, 0xe7, 0xbe, 0x23, 0x56, 0x2b, 0x36, 0x26, 0x09,
    0x50, 0x27, 0x2b, 0x33, 0x7a, 0xd6, 0x2d, 0x8c, 0x9e, 0xb0, 0x9c, 0xff, 0x26, 0x62, 0x6c, 0x29,
    0xe1, 0x68, 0xc3, 0x3d, 0x3b, 0x70, 0x1b, 0x2a, 0x8a, 0x75, 0x0b, 0xc8, 0x83, 0xbf, 0x0e, 0x69,
    0x2a, 0xf3, 0x8c, 0x46, 0x94, 0x9d, 0x3b, 0x2b, 0x28, 0x4b, 0x9f, 0xb4, 0x95, 0x10, 0x96, 0x63,
    0x1b, 0x4c, 0xa6, 0x78, 0xc5, 0x2f, 0x7d, 0x09, 0xa7, 0xf4, 0x02, 0x5e, 0xc0, 0x51, 0x01, 0x09,
    0x4d, 0x71, 0x43, 0x47, 0x63, 0xcd, 0xa1, 0x21, 0xc2, 0x66, 0x5c, 0x3a, 0x0a, 0xd2, 0x6a, 0x51,
    0x2f, 0x6b, 0xa1, 0x92, 0xf0, 0x30, 0xa3, 0xa2, 0xf7, 0xa9, 0xcb, 0x5f, 0xd5, 0x89, 0x47, 0xe2,
    0x46, 0x22, 0xf3, 0xbe, 0xd0, 0x66, 0xc9, 0xa8, 0xc4, 0xef, 0xa2, 0x54, 0x07, 0xe1, 0xfb, 0xe0,
    0x0d, 0x15, 0xeb, 0xaa, 0x6c, 0x83, 0x2d, 0xb4, 0x52, 0xfc, 0x99, 0xc3, 0xbd, 0x63, 0x48, 0x13,
    0xf4, 0xf9, 0x33, 0x1f, 0xf6, 0xab, 0x5b, 0x22, 0x45, 0x23, 0xed, 0x60, 0x9d, 0x31, 0x8d, 0xe1,
    0x70, 0xc8, 0xe8, 0x60, 0x5f, 0xb1, 0xbb, 0xab, 0x3a, 0x42, 0x59, 0x11, 0xa9, 0xc9, 0x4f, 0xda,
    0xae, 0x06, 0x1a, 0xb5, 0xd0, 0x27, 0x42, 0x90, 0x48, 0x6c, 0x38, 0x7b, 0xe8, 0x18, 0xc8, 0xb6,
    0x84, 0x64, 0xb8, 0x6b, 0xb0, 0xa8, 0x26, 0x9d, 0x23, 0xbc, 0x2a, 0x3f, 0x20, 0x2e, 0x6f, 0x23,
    0xaf, 0x85, 0x52, 0x8e, 0xf5, 0xa9, 0xa4, 0x4e, 0x45, 0xa5, 0xf5, 0xcd, 0xcd, 0x2a, 0x72, 0x77,
    0xa0, 0x34,
  ];

  const cert: Certificate = {
    encoding: 'Der',
    data: certDer,
  };

  const certChain: Certificate[] = [];
  const notAfter = '2026-08-18T09:00:11Z'; // Updated to match actual cert expiry

  try {
    const result = Crypto.verifyCert(cert, certChain, notAfter);
    return new Validation.ValidationResponse(
      result.trusted,
      result.trusted ? undefined : result.reason,
      undefined,
      undefined,
      {
        trusted: result.trusted.toString(),
        reason: result.reason || '',
        certEncoding: cert.encoding,
        chainLength: certChain.length.toString(),
        notAfter,
        certData: 'certificate0',
      },
    );
  } catch (error) {
    return new Validation.ValidationResponse(
      false,
      `Certificate verification failed: ${error}`,
      undefined,
      undefined,
      {
        trusted: 'false',
        reason: `Error: ${error}`,
        certEncoding: cert.encoding,
        chainLength: certChain.length.toString(),
        notAfter,
        certData: 'certificate0',
      },
    );
  }
}

/**
 * Even simpler failure test - just use empty data
 */
export function handleCryptoVerifyCertFailure(): Validation.ValidationResponse {
  const invalidCert: Certificate = {
    encoding: 'Der',
    data: [], // Empty data will definitely fail
  };

  const certChain: Certificate[] = [];
  const notAfter = '2025-12-31T23:59:59Z';

  try {
    const result = Crypto.verifyCert(invalidCert, certChain, notAfter);
    return new Validation.ValidationResponse(
      !result.trusted,
      result.trusted ? 'Unexpectedly trusted invalid certificate' : undefined,
      undefined,
      undefined,
      {
        trusted: result.trusted.toString(),
        reason: result.reason || '',
        certEncoding: invalidCert.encoding,
        chainLength: certChain.length.toString(),
        notAfter,
      },
    );
  } catch (error) {
    // Expected to fail - this is the success case for this test
    return new Validation.ValidationResponse(true, undefined, undefined, undefined, {
      trusted: 'false',
      reason: `Expected failure: ${error}`,
      certEncoding: invalidCert.encoding,
      chainLength: certChain.length.toString(),
      notAfter,
    });
  }
}
