#include <iostream>
#include <vector>
#include <chrono>
#include <numeric>
#include <memory>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sys/resource.h>

using namespace std;
using namespace std::chrono;

#define NUM_ITERATIONS 100

size_t getMemoryUsage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

EC_KEY* generateKeys(microseconds& parameterTime) {
    auto start = high_resolution_clock::now();
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key || !EC_KEY_generate_key(ec_key)) {
        cerr << "Error generating EC key pair\n";
        EC_KEY_free(ec_key);
        return nullptr;
    }
    auto end = high_resolution_clock::now();
    parameterTime = duration_cast<microseconds>(end - start);
    return ec_key;
}

bool signMessage(EC_KEY* ec_key, const unsigned char* msg, size_t msgLen, unique_ptr<unsigned char[]>& sig, unsigned int& sigLen, microseconds& signatureTime, double& bandwidthEfficiency) {
    sigLen = ECDSA_size(ec_key);
    sig.reset(new unsigned char[sigLen]);
    SHA256_CTX shaCtx;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&shaCtx);
    SHA256_Update(&shaCtx, msg, msgLen);
    SHA256_Final(hash, &shaCtx);
    auto start = high_resolution_clock::now();
    if (!ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, sig.get(), &sigLen, ec_key)) {
        cerr << "Error signing message\n";
        return false;
    }
    auto end = high_resolution_clock::now();
    signatureTime = duration_cast<microseconds>(end - start);
    bandwidthEfficiency = (sigLen / static_cast<double>(msgLen)) * 100.0;
    return true;
}

bool verifySignature(EC_KEY* ec_key, const unsigned char* msg, size_t msgLen, const unique_ptr<unsigned char[]>& sig, unsigned int sigLen, microseconds& verificationTime) {
    SHA256_CTX shaCtx;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&shaCtx);
    SHA256_Update(&shaCtx, msg, msgLen);
    SHA256_Final(hash, &shaCtx);
    auto start = high_resolution_clock::now();
    int valid = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, sig.get(), sigLen, ec_key);
    auto end = high_resolution_clock::now();
    verificationTime = duration_cast<microseconds>(end - start);
    return valid == 1;
}

int main() {
  vector<int> message_sizes = {64, 128, 256 };
  for (int MESSAGE_SIZE : message_sizes) {
      cout << "\nTesting for message size: " << MESSAGE_SIZE << " bytes\n";
      vector<microseconds> parameterTimes, signatureTimes, verificationTimes;
      vector<size_t> memoryUsages;
      vector<double> bandwidthEfficiencies;

      for (int i = 0; i < NUM_ITERATIONS; i++) {
          microseconds parameterTime;
          EC_KEY* ec_key = generateKeys(parameterTime);
          if (!ec_key) return 1;

          vector<unsigned char> message(MESSAGE_SIZE);
          if (RAND_bytes(message.data(), MESSAGE_SIZE) != 1) {
              cerr << "Error generating random message\n";
              EC_KEY_free(ec_key);
              return 1;
          }

          unique_ptr<unsigned char[]> signature;
          unsigned int signatureLen = 0;
          size_t memoryBefore = getMemoryUsage();
          microseconds signatureTime;
          double bandwidthEfficiency;

          if (!signMessage(ec_key, message.data(), MESSAGE_SIZE, signature, signatureLen, signatureTime, bandwidthEfficiency)) {
              EC_KEY_free(ec_key);
              return 1;
          }

          microseconds verificationTime;
          if (!verifySignature(ec_key, message.data(), MESSAGE_SIZE, signature, signatureLen, verificationTime)) {
              EC_KEY_free(ec_key);
              return 1;
          }

          size_t memoryAfter = getMemoryUsage();
          parameterTimes.push_back(parameterTime);
          signatureTimes.push_back(signatureTime);
          verificationTimes.push_back(verificationTime);
          bandwidthEfficiencies.push_back(bandwidthEfficiency);
          memoryUsages.push_back(memoryAfter);

          EC_KEY_free(ec_key);
      }

      double avgParameterTime = accumulate(parameterTimes.begin(), parameterTimes.end(), microseconds(0)).count() / static_cast<double>(NUM_ITERATIONS);
      double avgSignatureTime = accumulate(signatureTimes.begin(), signatureTimes.end(), microseconds(0)).count() / static_cast<double>(NUM_ITERATIONS);
      double avgVerificationTime = accumulate(verificationTimes.begin(), verificationTimes.end(), microseconds(0)).count() / static_cast<double>(NUM_ITERATIONS);
      double avgMemoryUsage = accumulate(memoryUsages.begin(), memoryUsages.end(), 0.0) / NUM_ITERATIONS;
      double avgBandwidthEfficiency = accumulate(bandwidthEfficiencies.begin(), bandwidthEfficiencies.end(), 0.0) / NUM_ITERATIONS;

      cout << "==== AVERAGE METRICS OVER " << NUM_ITERATIONS << " ITERATIONS ====\n";
      cout << "Average Parameter Generation Time: " << avgParameterTime << " microseconds\n";
      cout << "Average Signature Time: " << avgSignatureTime << " microseconds\n";
      cout << "Average Verification Time: " << avgVerificationTime << " microseconds\n";
      cout << "Average Memory Usage: " << avgMemoryUsage / 1024 << " KB\n";
      cout << "Average Bandwidth Efficiency: " << avgBandwidthEfficiency << " %\n";
  }
  return 0;
}
