package com.example.keystoredemo.network

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

object ApiClient {
    var SERVER_URL = "http://localhost:8080"

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    private val gson = Gson()
    private val JSON = "application/json; charset=utf-8".toMediaType()

    suspend fun registerStart(userId: String): Map<String, String> = withContext(Dispatchers.IO) {
        val body = gson.toJson(mapOf("userId" to userId)).toRequestBody(JSON)
        val request = Request.Builder()
            .url("$SERVER_URL/api/register/start")
            .post(body)
            .build()
        val response = client.newCall(request).execute()
        val responseBody = response.body?.string() ?: throw Exception("Empty response")
        if (!response.isSuccessful) throw Exception(parseError(responseBody))
        gson.fromJson(responseBody, object : TypeToken<Map<String, String>>() {}.type)
    }

    suspend fun registerFinish(
        sessionId: String,
        userId: String,
        certificateChain: List<String>
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val payload = mapOf(
            "sessionId" to sessionId,
            "userId" to userId,
            "certificateChain" to certificateChain
        )
        val body = gson.toJson(payload).toRequestBody(JSON)
        val request = Request.Builder()
            .url("$SERVER_URL/api/register/finish")
            .post(body)
            .build()
        val response = client.newCall(request).execute()
        val responseBody = response.body?.string() ?: throw Exception("Empty response")
        if (!response.isSuccessful) throw Exception(parseError(responseBody))
        gson.fromJson(responseBody, object : TypeToken<Map<String, Any>>() {}.type)
    }

    suspend fun authStart(userId: String): Map<String, String> = withContext(Dispatchers.IO) {
        val body = gson.toJson(mapOf("userId" to userId)).toRequestBody(JSON)
        val request = Request.Builder()
            .url("$SERVER_URL/api/auth/start")
            .post(body)
            .build()
        val response = client.newCall(request).execute()
        val responseBody = response.body?.string() ?: throw Exception("Empty response")
        if (!response.isSuccessful) throw Exception(parseError(responseBody))
        gson.fromJson(responseBody, object : TypeToken<Map<String, String>>() {}.type)
    }

    suspend fun authFinish(
        sessionId: String,
        userId: String,
        authenticatorData: String,
        clientDataHash: String,
        signature: String
    ): Map<String, Any> = withContext(Dispatchers.IO) {
        val payload = mapOf(
            "sessionId" to sessionId,
            "userId" to userId,
            "authenticatorData" to authenticatorData,
            "clientDataHash" to clientDataHash,
            "signature" to signature
        )
        val body = gson.toJson(payload).toRequestBody(JSON)
        val request = Request.Builder()
            .url("$SERVER_URL/api/auth/finish")
            .post(body)
            .build()
        val response = client.newCall(request).execute()
        val responseBody = response.body?.string() ?: throw Exception("Empty response")
        if (!response.isSuccessful) throw Exception(parseError(responseBody))
        gson.fromJson(responseBody, object : TypeToken<Map<String, Any>>() {}.type)
    }

    private fun parseError(responseBody: String): String {
        return try {
            val map: Map<String, String> = gson.fromJson(responseBody, object : TypeToken<Map<String, String>>() {}.type)
            map["error"] ?: responseBody
        } catch (e: Exception) {
            responseBody
        }
    }
}
