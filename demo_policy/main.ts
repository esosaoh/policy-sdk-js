import { Validation } from '../js/kubewarden/validation';
import { writeOutput } from '../js/protocol';

import { PolicySettings } from './policy_settings';
import {
  handleOciManifestDigestSuccess,
  handleOciManifestDigestFailure,
  handleDnsLookupSuccess,
  handleDnsLookupFailure,
  handleOciManifestFailure,
  handleOciManifestSuccess,
  handleOciManifestAndConfigFailure,
  handleOciManifestAndConfigSuccess,
  handlePrivilegedContainerValidation,
  handleGetResourceSuccess,
  handleGetResourceFailure,
} from './test_scenarios';

declare function policyAction(): string;

/**
 * Validates a Kubernetes admission request to ensure that privileged containers
 * are not allowed unless they are in an ignored namespace.
 * @returns {void}
 */
function validate() {
  const validationRequest = Validation.readValidationRequest();
  const settings = validationRequest.settings as PolicySettings;
  let response: Validation.ValidationResponse;

  console.error('Settings:', JSON.stringify(settings));

  switch (settings.testScenario) {
    case 'oci-manifest-digest-success': {
      response = handleOciManifestDigestSuccess();
      break;
    }
    case 'oci-manifest-digest-failure': {
      response = handleOciManifestDigestFailure();
      break;
    }
    case 'dns-lookup-success': {
      response = handleDnsLookupSuccess();
      break;
    }
    case 'dns-lookup-failure': {
      response = handleDnsLookupFailure();
      break;
    }
    case 'oci-manifest-success': {
      response = handleOciManifestSuccess();
      break;
    }
    case 'oci-manifest-failure': {
      response = handleOciManifestFailure();
      break;
    }
    case 'oci-manifest-and-config-success': {
      response = handleOciManifestAndConfigSuccess();
      break;
    }
    case 'oci-manifest-and-config-failure': {
      response = handleOciManifestAndConfigFailure();
      break;
    }
    case 'get-resource-success': {
      response = handleGetResourceSuccess();
      break;
    }
    case 'get-resource-failure': {
      response = handleGetResourceFailure();
      break;
    }
    default: {
      response = handlePrivilegedContainerValidation(validationRequest, settings);
      break;
    }
  }

  writeOutput(response);
}

function validateSettings() {
  try {
    const settingsInput = Validation.readValidationRequest(); // already the settings
    const settings = new PolicySettings(settingsInput);
    const response = settings.validate();
    writeOutput(response);
  } catch (err) {
    console.error('validateSettings error:', err);
    const response = new Validation.SettingsValidationResponse(false, `${err}`);
    writeOutput(response);
  }
}

try {
  const action = policyAction();
  console.error('Action:', action);

  switch (action) {
    case 'validate': {
      validate();
      break;
    }
    case 'validate-settings': {
      validateSettings();
      break;
    }
    default: {
      console.error('Unknown action:', action);
      const response = new Validation.ValidationResponse(false, 'wrong invocation');
      writeOutput(response);
    }
  }
} catch (error) {
  console.error('error:', error);
  const response = new Validation.ValidationResponse(false, 'wrong invocation');
  writeOutput(response);
}
