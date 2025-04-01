#include <iostream>
#include <vector>
#include <chrono>
#include <numeric>
#include <memory>
#include <openssl/dsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sys/resource.h>  // For memory usage

using namespace std;
using namespace std::chrono;

#define KEY_SIZE 2048  // DSA Key size
#define NUM_ITERATIONS 100

size_t getMemoryUsage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

DSA* generateKeys(microseconds& parameterTime) {
    DSA* dsa = DSA_new();
    if (!dsa) {
        cerr << "Error creating DSA object\n";
        return nullptr;
    }

    auto start = high_resolution_clock::now();

    if (!DSA_generate_parameters_ex(dsa, KEY_SIZE, nullptr, 0, nullptr, nullptr, nullptr)) {
        cerr << "Error generating DSA parameters\n";
        DSA_free(dsa);
        return nullptr;
    }

    if (!DSA_generate_key(dsa)) {
        cerr << "Error generating DSA key pair\n";
        DSA_free(dsa);
        return nullptr;
    }

    auto end = high_resolution_clock::now();
    parameterTime = duration_cast<microseconds>(end - start);

    return dsa;
}

bool signMessage(DSA* dsa, const unsigned char* msg, size_t msgLen, unique_ptr<unsigned char[]>& sig, unsigned int& sigLen, microseconds& signatureTime, double& bandwidthEfficiency) {
    sig.reset(new unsigned char[DSA_size(dsa)]);
    SHA256_CTX shaCtx;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_Init(&shaCtx);
    SHA256_Update(&shaCtx, msg, msgLen);
    SHA256_Final(hash, &shaCtx);

    auto start = high_resolution_clock::now();
    sigLen = 0;

    if (!DSA_sign(0, hash, SHA256_DIGEST_LENGTH, sig.get(), &sigLen, dsa)) {
        cerr << "Error signing message\n";
        return false;
    }

    auto end = high_resolution_clock::now();
    signatureTime = duration_cast<microseconds>(end - start);
    bandwidthEfficiency = (sigLen / static_cast<double>(msgLen)) * 100.0;

    return true;
}

bool verifySignature(DSA* dsa, const unsigned char* msg, size_t msgLen, const unique_ptr<unsigned char[]>& sig, unsigned int sigLen, microseconds& verificationTime) {
    SHA256_CTX shaCtx;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_Init(&shaCtx);
    SHA256_Update(&shaCtx, msg, msgLen);
    SHA256_Final(hash, &shaCtx);

    auto start = high_resolution_clock::now();
    int valid = DSA_verify(0, hash, SHA256_DIGEST_LENGTH, sig.get(), sigLen, dsa);
    auto end = high_resolution_clock::now();

    verificationTime = duration_cast<microseconds>(end - start);
    return valid == 1;
}

int main() {
    vector<int> messageSizes = {64, 128, 256};

    for (int messageSize : messageSizes) {
        cout << "\n==== TESTING WITH MESSAGE SIZE: " << messageSize << " BYTES ====\n";
        vector<microseconds> parameterTimes, signatureTimes, verificationTimes;
        vector<size_t> memoryUsages;
        vector<double> bandwidthEfficiencies;

        for (int i = 0; i < NUM_ITERATIONS; i++) {
            microseconds parameterTime;
            DSA* dsa = generateKeys(parameterTime);

            unsigned char* message = new unsigned char[messageSize];
            RAND_bytes(message, messageSize);

            unique_ptr<unsigned char[]> signature;
            unsigned int signatureLen = 0;

            size_t memoryBefore = getMemoryUsage();

            microseconds signatureTime;
            double bandwidthEfficiency;
            signMessage(dsa, message, messageSize, signature, signatureLen, signatureTime, bandwidthEfficiency);

            microseconds verificationTime;
            verifySignature(dsa, message, messageSize, signature, signatureLen, verificationTime);

            size_t memoryAfter = getMemoryUsage();

            parameterTimes.push_back(parameterTime);
            signatureTimes.push_back(signatureTime);
            verificationTimes.push_back(verificationTime);
            bandwidthEfficiencies.push_back(bandwidthEfficiency);
            memoryUsages.push_back(memoryAfter);

            delete[] message;
            DSA_free(dsa);
        }

        double avgParameterTime = accumulate(parameterTimes.begin(), parameterTimes.end(), microseconds(0)).count() / static_cast<double>(NUM_ITERATIONS);
        double avgSignatureTime = accumulate(signatureTimes.begin(), signatureTimes.end(), microseconds(0)).count() / static_cast<double>(NUM_ITERATIONS);
        double avgVerificationTime = accumulate(verificationTimes.begin(), verificationTimes.end(), microseconds(0)).count() / static_cast<double>(NUM_ITERATIONS);
        double avgMemoryUsage = accumulate(memoryUsages.begin(), memoryUsages.end(), 0.0) / NUM_ITERATIONS;
        double avgBandwidthEfficiency = accumulate(bandwidthEfficiencies.begin(), bandwidthEfficiencies.end(), 0.0) / NUM_ITERATIONS;

        cout << "Average Parameter Generation Time: " << avgParameterTime << " microseconds" << endl;
        cout << "Average Signature Time: " << avgSignatureTime << " microseconds" << endl;
        cout << "Average Verification Time: " << avgVerificationTime << " microseconds" << endl;
        cout << "Average Memory Usage: " << avgMemoryUsage / 1024 << " KB" << endl;
        cout << "Average Bandwidth Efficiency: " << avgBandwidthEfficiency << " %" << endl;
    }

    return 0;
}
