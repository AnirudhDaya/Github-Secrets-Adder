// app/api/github-secrets/route.ts
import { NextRequest, NextResponse } from 'next/server';
import _sodium from 'libsodium-wrappers';

// Parse multipart form data
async function parseFormData(req: NextRequest) {
  const formData = await req.formData();
  const repo = formData.get('repo') as string;
  const pat = formData.get('pat') as string;
  
  // Check if env is provided as a file or a string
  let envText: string;
  const envParam = formData.get('env');
  if (envParam instanceof File) {
    envText = await envParam.text();
  } else {
    envText = envParam as string;
  }

  if (!repo || !pat || !envText) {
    throw new Error('Missing required parameters: repo, pat, or env');
  }
  
  return { repo, pat, envText };
}

// Parse env file content into key-value pairs
function parseEnvContent(envContent: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = envContent.split('\n');
  
  console.log(`Parsing ${lines.length} lines from env content`);
  
  let currentKey = '';
  let inValue = false;
  let value = '';
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    
    // Skip empty lines and comments
    if (!line || line.startsWith('#')) continue;
    
    if (!inValue) {
      // Match key=value pattern
      const match = line.match(/^([A-Za-z0-9_]+)=(.*)/);
      if (match) {
        currentKey = match[1];
        value = match[2];
        
        // Check if value starts with a quote but doesn't end with one
        if (value.startsWith('"') && !value.endsWith('"') && !value.endsWith('\\"')) {
          // This is the start of a multiline value
          inValue = true;
          // Remove the starting quote
          value = value.substring(1);
        } else {
          // Single line value, remove quotes if present
          value = value.replace(/^["'](.*)["']$/, '$1');
          result[currentKey] = value;
          console.log(`Added single-line secret: ${currentKey} (${value.length} chars)`);
          currentKey = '';
          value = '';
        }
      } else {
        console.log(`Line doesn't match key=value pattern: ${line.substring(0, 20)}...`);
      }
    } else {
      // We're in a multiline value
      // Check if this line ends the value
      if (line.endsWith('"') && !line.endsWith('\\"')) {
        // This ends the multiline value
        value = value + '\n' + line.slice(0, -1);
        inValue = false;
        result[currentKey] = value;
        console.log(`Added multi-line secret: ${currentKey} (${value.length} chars)`);
        currentKey = '';
        value = '';
      } else {
        // This is a continuation of the multiline value
        value = value + '\n' + line;
      }
    }
  }
  
  // If we're still in a multiline value at the end, process it anyway
  if (inValue && currentKey) {
    result[currentKey] = value;
    console.log(`Added unterminated multi-line secret: ${currentKey} (${value.length} chars)`);
  }
  
  console.log(`Parsed ${Object.keys(result).length} secrets from env file`);
  return result;
}

// Get repository public key
async function getPublicKey(repo: string, pat: string) {
  const [org, repoName] = repo.split('/');
  console.log(repoName)
  // Try repository public key first
  let response = await fetch(`https://api.github.com/repos/${repo}/actions/secrets/public-key`, {
    headers: {
      'Authorization': `token ${pat}`,
      'Accept': 'application/vnd.github.v3+json'
    }
  });
  
  let data = await response.json();
  
  if (response.status === 404) {
    // Try organization public key
    response = await fetch(`https://api.github.com/orgs/${org}/actions/secrets/public-key`, {
      headers: {
        'Authorization': `token ${pat}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });
    
    data = await response.json();
    
    if (response.status === 404) {
      throw new Error('Neither repository nor organization public key found');
    }
    
    return { 
      publicKey: data.key, 
      keyId: data.key_id, 
      isOrg: true 
    };
  }
  
  return { 
    publicKey: data.key, 
    keyId: data.key_id, 
    isOrg: false 
  };
}

// Encrypt value using libsodium for GitHub API
async function encryptValue(value: string, publicKey: string): Promise<string> {
  // Wait for sodium to initialize
  await _sodium.ready;
  const sodium = _sodium;
  
  // Convert the public key from base64 to Uint8Array
  const publicKeyBytes = sodium.from_base64(publicKey, sodium.base64_variants.ORIGINAL);
  
  // Convert the secret value to Uint8Array
  const secretBytes = sodium.from_string(value);
  
  // Encrypt the secret using sodium's box seal method
  const encryptedBytes = sodium.crypto_box_seal(secretBytes, publicKeyBytes);
  
  // Convert the encrypted bytes to base64
  const encryptedValue = sodium.to_base64(encryptedBytes, sodium.base64_variants.ORIGINAL);
  
  return encryptedValue;
}

// Set secret in GitHub repository using proper encryption
async function setSecret(key: string, value: string, repo: string, pat: string, keyInfo: { publicKey: string, keyId: string, isOrg: boolean }) {
  const [org, repoName] = repo.split('/');
  console.log(repoName)
  // Encrypt the value using libsodium with GitHub's public key
  const encryptedValue = await encryptValue(value, keyInfo.publicKey);
  
  let url;
  
  if (keyInfo.isOrg) {
    // For organization secrets
    url = `https://api.github.com/orgs/${org}/actions/secrets/${key}`;
  } else {
    // For repository secrets
    url = `https://api.github.com/repos/${repo}/actions/secrets/${key}`;
  }
  
  const requestBody = {
    encrypted_value: encryptedValue,
    key_id: keyInfo.keyId,
    ...(keyInfo.isOrg ? { visibility: "all" } : {})
  };
  
  console.log(`Setting secret ${key} at URL: ${url}`);
  
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      'Authorization': `token ${pat}`,
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(requestBody)
  });
  
  // Read the response body
  let responseBody;
  try {
    responseBody = await response.text();
  } catch {
    responseBody = "Failed to read response body";
  }
  
  console.log(`Secret ${key} response status: ${response.status}, body: ${responseBody}`);
  
  return { 
    status: response.status, 
    statusText: response.statusText,
    success: response.status === 201 || response.status === 204,
    response: responseBody
  };
}

// Main API handler
export async function POST(req: NextRequest) {
  try {
    console.log("Processing GitHub secrets request");
    
    // Parse the form data
    const { repo, pat, envText } = await parseFormData(req);
    console.log(`Parsed form data for repo: ${repo}, env length: ${envText.length} chars`);
    
    // Check repository exists and token has access
    const repoCheckResponse = await fetch(`https://api.github.com/repos/${repo}`, {
      headers: {
        'Authorization': `token ${pat}`
      }
    });
    
    if (repoCheckResponse.status === 404) {
      console.error("Repository not found or token doesn't have access");
      return NextResponse.json(
        { success: false, variables: ["Repository access error"] },
        { status: 404 }
      );
    }
    
    // Get the public key
    const keyInfo = await getPublicKey(repo, pat);
    console.log(`Retrieved public key: ${keyInfo.keyId}, isOrg: ${keyInfo.isOrg}`);
    
    // Parse env file
    const secrets = parseEnvContent(envText);
    console.log(`Parsed ${Object.keys(secrets).length} secrets from env file`);
    
    // Process each secret
    const results = [];
    const failedSecrets = [];
    const successSecrets = [];
    
    for (const [key, value] of Object.entries(secrets)) {
      console.log(`Processing secret: ${key}`);
      try {
        const result = await setSecret(key, value, repo, pat, keyInfo);
        console.log(`Secret ${key} set with status: ${result.status}`);
        
        if (!result.success) {
          failedSecrets.push(key);
        }
        else{
          successSecrets.push(key)
        }
        
        results.push({
          key,
          success: result.success,
          status: result.status,
          statusText: result.statusText,
          response: result.response
        });
      } catch (error) {
        console.error(`Error setting secret ${key}:`, error);
        failedSecrets.push(key);
        results.push({
          key,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }
    
    // Check if all secrets were set successfully
    if (failedSecrets.length === 0) {
      return NextResponse.json({
        success: true,
        variables:  successSecrets
      });
    } else {
      return NextResponse.json({
        success: false,
        variables: failedSecrets
      });
    }
    
  } catch (error) {
    console.error('Error processing GitHub secrets:', error);
    return NextResponse.json({
      success: false,
      variables: [error instanceof Error ? error.message : 'Unknown error']
    }, { status: 500 });
  }
}