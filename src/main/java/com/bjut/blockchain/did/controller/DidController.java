package com.bjut.blockchain.did.controller;

import com.bjut.blockchain.did.dto.*; // 引入所有DTO
import com.bjut.blockchain.did.model.Did;
import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.did.model.DidDocument.VerificationMethod;
import com.bjut.blockchain.did.service.DidAuthenticationService;
import com.bjut.blockchain.did.service.DidService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.*;

@RestController
@RequestMapping("/api/did")
public class DidController {

    private static final Logger logger = LoggerFactory.getLogger(DidController.class);
    private final DidService didService;
    private final DidAuthenticationService didAuthenticationService;
    private final ObjectMapper objectMapper;

    @Autowired
    public DidController(DidService didService,
                         DidAuthenticationService didAuthenticationService,
                         ObjectMapper objectMapper) {
        this.didService = didService;
        this.didAuthenticationService = didAuthenticationService;
        this.objectMapper = objectMapper;
    }

    // --- DTOs (确保它们在 com.bjut.blockchain.did.dto 包中) ---
    // ChallengeRequest, VerificationRequest, CreateDidRequest
    // DidPublicKeyInfo, DidDocumentUpdateRequest, DidKeyRemovalRequest

    // --- 身份认证端点 (登录挑战、验证签名、登出) ---
    // ... (这些端点与上一版本相同，为简洁省略) ...
    @PostMapping("/auth/challenge")
    public ResponseEntity<Map<String, String>> requestLoginChallenge(@RequestBody ChallengeRequest challengeRequest, HttpServletRequest httpRequest) {
        String did = challengeRequest.getDid();
        if (did == null || did.isEmpty()) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "必须提供DID。"));
        }
        DidDocument doc = didService.getDidDocument(did);
        if (doc == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.singletonMap("error", "找不到DID: " + did));
        }
        if (doc.getAuthentication() == null || doc.getAuthentication().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error", "DID " + did + " 没有注册可用于认证的密钥。"));
        }
        String challenge = UUID.randomUUID().toString();
        HttpSession session = httpRequest.getSession(true);
        session.setAttribute("login_challenge", challenge);
        session.setAttribute("login_challenge_did", did);
        Map<String, String> response = new HashMap<>();
        response.put("did", did);
        response.put("challenge", challenge);
        if (!doc.getAuthentication().isEmpty()) {
            response.put("keyIdHint", doc.getAuthentication().get(0));
        }
        logger.info("已为 DID '{}' 在会话 {} 中生成登录挑战: '{}'", did, session.getId(), challenge);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/auth/verify")
    public ResponseEntity<Map<String, Object>> verifyLoginSignature(@RequestBody VerificationRequest verificationRequest, HttpServletRequest httpRequest) {
        Map<String, Object> response = new HashMap<>();
        String did = verificationRequest.getDid();
        String clientChallenge = verificationRequest.getChallenge();
        String signatureBase64 = verificationRequest.getSignatureBase64();
        String keyId = verificationRequest.getKeyId();

        if (did == null || clientChallenge == null || signatureBase64 == null || keyId == null || keyId.isEmpty()) {
            response.put("success", false); response.put("message", "请求中缺少 did, challenge, signatureBase64 或 keyId。");
            return ResponseEntity.badRequest().body(response);
        }
        HttpSession session = httpRequest.getSession(false);
        if (session == null) {
            response.put("success", false); response.put("message", "会话不存在或已过期。请重新请求挑战。");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        String serverChallenge = (String) session.getAttribute("login_challenge");
        String challengeDid = (String) session.getAttribute("login_challenge_did");
        session.removeAttribute("login_challenge");
        session.removeAttribute("login_challenge_did");

        if (serverChallenge == null || challengeDid == null || !challengeDid.equals(did) || !serverChallenge.equals(clientChallenge)) {
            response.put("success", false); response.put("message", "挑战无效或不匹配。请重新请求挑战。");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        boolean isAuthenticated = didAuthenticationService.verifyDidControl(did, serverChallenge, signatureBase64, keyId);
        if (isAuthenticated) {
            HttpSession userSession = httpRequest.getSession(true);
            userSession.setAttribute("loggedInUserDid", did);
            userSession.setMaxInactiveInterval(30 * 60);
            response.put("success", true); response.put("message", "登录成功！");
            return ResponseEntity.ok(response);
        } else {
            response.put("success", false); response.put("message", "登录失败：签名验证失败或提供的密钥无效。");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            response.put("success", true); response.put("message", "成功登出！");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("success", false); response.put("message", "登出过程中发生错误。");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    // --- DID管理端点 ---
    @PostMapping("/create")
    public ResponseEntity<?> createDid(@RequestBody CreateDidRequest createDidRequest) {
        String publicKeyBase64 = createDidRequest.getPublicKeyBase64();
        if (publicKeyBase64 == null || publicKeyBase64.isEmpty()) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "必须在请求体中提供 publicKeyBase64。"));
        }
        try {
            Did newDid = didService.createDid(publicKeyBase64);
            if (newDid == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.singletonMap("error", "创建 DID 对象失败。"));
            }
            DidDocument didDocument = didService.getDidDocument(newDid.getDidString());
            if (didDocument != null) {
                Map<String, Object> responseMap = new HashMap<>();
                responseMap.put("didDocument", didDocument);
                return ResponseEntity.ok(responseMap);
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.singletonMap("error", "创建后检索 DID 文档失败。"));
            }
        } catch (Exception e) {
            logger.error("创建 DID 时发生意外错误: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Collections.singletonMap("error", "DID 创建期间发生意外错误：" + e.getMessage()));
        }
    }

    @GetMapping("/resolve/{didString:.+}")
    public ResponseEntity<DidDocument> resolveDid(@PathVariable String didString) {
        DidDocument didDocument = didService.getDidDocument(didString);
        if (didDocument != null) {
            return ResponseEntity.ok(didDocument);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/list")
    public ResponseEntity<Set<String>> listDids() {
        return ResponseEntity.ok(didService.getAllDids());
    }

    // --- DID文档更新端点 ---

    /**
     * 阶段1：为【添加密钥】到DID文档操作请求一个挑战。
     * POST /api/did/update/add-key/challenge
     * 请求体: Map 包含 "did" (要更新的DID), "authorizingKeyId" (用于授权的现有密钥ID)
     */
    @PostMapping("/update/add-key/challenge")
    public ResponseEntity<Map<String, String>> requestAddKeyChallenge(@RequestBody Map<String, String> payload, HttpServletRequest httpRequest) {
        String didToUpdate = payload.get("did");
        String authorizingKeyId = payload.get("authorizingKeyId");

        if (didToUpdate == null || didToUpdate.isEmpty() || authorizingKeyId == null || authorizingKeyId.isEmpty()) {
            logger.warn("请求添加密钥挑战失败：缺少 'did' 或 'authorizingKeyId' 参数。");
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "必须提供 'did' 和 'authorizingKeyId'。"));
        }

        DidDocument currentDoc = didService.getDidDocument(didToUpdate);
        if (currentDoc == null) {
            logger.warn("请求添加密钥挑战失败：DID '{}' 未找到。", didToUpdate);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.singletonMap("error", "DID '" + didToUpdate + "' 未找到。"));
        }

        boolean authKeyIsValid = currentDoc.getVerificationMethod().stream().anyMatch(vm -> authorizingKeyId.equals(vm.getId())) ||
                (currentDoc.getAuthentication() != null && currentDoc.getAuthentication().contains(authorizingKeyId));

        if (!authKeyIsValid) {
            logger.warn("请求添加密钥挑战失败：授权密钥ID '{}' 在DID '{}' 的验证方法或认证关系中未找到。", authorizingKeyId, didToUpdate);
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "提供的授权密钥ID '" + authorizingKeyId + "' 无效或不属于该DID。"));
        }

        String challenge = UUID.randomUUID().toString();
        HttpSession session = httpRequest.getSession(true);
        // 为添加密钥操作使用特定的会话挑战键
        String sessionChallengeKey = "add_key_challenge_" + didToUpdate + "_" + authorizingKeyId.replaceAll("[^a-zA-Z0-9_-]", "_");
        session.setAttribute(sessionChallengeKey, challenge);

        Map<String, String> response = new HashMap<>();
        response.put("did", didToUpdate);
        response.put("authorizingKeyId", authorizingKeyId);
        response.put("challenge", challenge);

        logger.info("为DID '{}' 的添加密钥操作 (授权密钥ID: {}) 生成挑战: '{}' (会话键: {})", didToUpdate, authorizingKeyId, challenge, sessionChallengeKey);
        return ResponseEntity.ok(response);
    }

    /**
     * 阶段2：执行DID文档更新 - 添加新的验证方法。
     * POST /api/did/update/add-key/execute
     * 请求体: {@link com.bjut.blockchain.did.dto.DidDocumentUpdateRequest}
     */
    @PostMapping("/update/add-key/execute")
    @Transactional
    public ResponseEntity<Map<String, Object>> executeAddKey(@RequestBody DidDocumentUpdateRequest updateRequest, HttpServletRequest httpRequest) {
        Map<String, Object> response = new HashMap<>();
        if (updateRequest == null || updateRequest.getDid() == null || updateRequest.getNewPublicKeyInfo() == null ||
                updateRequest.getAuthorizingKeyId() == null || updateRequest.getChallenge() == null || updateRequest.getSignatureBase64() == null) {
            response.put("success", false); response.put("message", "请求体不完整。");
            return ResponseEntity.badRequest().body(response);
        }
        DidPublicKeyInfo newKeyDto = updateRequest.getNewPublicKeyInfo();
        if (newKeyDto.getPublicKeyBase64() == null || newKeyDto.getType() == null ||
                newKeyDto.getIdFragment() == null || newKeyDto.getIdFragment().trim().isEmpty()) {
            response.put("success", false); response.put("message", "新公钥信息 (publicKeyBase64, type, idFragment) 不完整或idFragment为空。");
            return ResponseEntity.badRequest().body(response);
        }

        HttpSession session = httpRequest.getSession(false);
        if (session == null) {
            response.put("success", false); response.put("message", "会话不存在或已过期。");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        String sessionChallengeKey = "add_key_challenge_" + updateRequest.getDid() + "_" + updateRequest.getAuthorizingKeyId().replaceAll("[^a-zA-Z0-9_-]", "_");
        String serverChallenge = (String) session.getAttribute(sessionChallengeKey);
        session.removeAttribute(sessionChallengeKey);

        if (serverChallenge == null || !serverChallenge.equals(updateRequest.getChallenge())) {
            response.put("success", false); response.put("message", "挑战无效、不匹配或已过期。");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        Map<String, Object> dataToSignMap = new LinkedHashMap<>();
        dataToSignMap.put("operationType", "addKey");
        dataToSignMap.put("did", updateRequest.getDid());
        dataToSignMap.put("authorizingKeyId", updateRequest.getAuthorizingKeyId());
        dataToSignMap.put("challenge", serverChallenge);
        dataToSignMap.put("newPublicKeyInfo", newKeyDto);

        String canonicalPayloadToVerify;
        try {
            canonicalPayloadToVerify = objectMapper.writeValueAsString(dataToSignMap);
        } catch (JsonProcessingException e) {
            response.put("success", false); response.put("message", "内部服务器错误：无法准备验证数据。");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
        logger.debug("为DID '{}' 添加密钥操作的待验证签名数据: {}", updateRequest.getDid(), canonicalPayloadToVerify);

        boolean signatureIsValid = didAuthenticationService.verifyDidControl(
                updateRequest.getDid(), canonicalPayloadToVerify,
                updateRequest.getSignatureBase64(), updateRequest.getAuthorizingKeyId());

        if (!signatureIsValid) {
            response.put("success", false); response.put("message", "签名验证失败。无法授权此添加密钥操作。");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        VerificationMethod newVm = new VerificationMethod();
        String fullNewKeyId = updateRequest.getDid() + "#" + newKeyDto.getIdFragment();
        newVm.setId(fullNewKeyId);
        newVm.setType(newKeyDto.getType());
        newVm.setPublicKeyBase64(newKeyDto.getPublicKeyBase64());
        newVm.setController(newKeyDto.getController() != null && !newKeyDto.getController().isEmpty()
                ? newKeyDto.getController() : updateRequest.getDid());
        try {
            DidDocument updatedDocument = didService.addVerificationMethodToDocument(updateRequest.getDid(), newVm);
            if (updatedDocument != null) {
                response.put("success", true); response.put("message", "DID文档更新成功！新的验证方法已添加。");
                response.put("updatedDidDocument", updatedDocument);
                return ResponseEntity.ok(response);
            } else {
                response.put("success", false); response.put("message", "DID文档更新失败（可能是DID不存在或KeyID冲突）。");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
            }
        } catch (Exception e) {
            response.put("success", false); response.put("message", "DID文档更新时发生内部错误：" + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * 阶段1：为【移除密钥】从DID文档操作请求一个挑战。
     * POST /api/did/update/remove-key/challenge
     * 请求体: Map 包含 "did", "authorizingKeyId", "keyIdToRemove"
     */
    @PostMapping("/update/remove-key/challenge")
    public ResponseEntity<Map<String, String>> requestRemoveKeyChallenge(@RequestBody Map<String, String> payload, HttpServletRequest httpRequest) {
        String didToUpdate = payload.get("did");
        String authorizingKeyId = payload.get("authorizingKeyId");
        String keyIdToRemove = payload.get("keyIdToRemove");

        if (didToUpdate == null || authorizingKeyId == null || keyIdToRemove == null ||
                didToUpdate.isEmpty() || authorizingKeyId.isEmpty() || keyIdToRemove.isEmpty()) {
            logger.warn("请求移除密钥挑战失败：缺少 'did', 'authorizingKeyId', 或 'keyIdToRemove' 参数。");
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "必须提供 'did', 'authorizingKeyId', 和 'keyIdToRemove'。"));
        }

        DidDocument currentDoc = didService.getDidDocument(didToUpdate);
        if (currentDoc == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.singletonMap("error", "DID '" + didToUpdate + "' 未找到。"));
        }

        boolean authKeyExists = currentDoc.getVerificationMethod().stream().anyMatch(vm -> authorizingKeyId.equals(vm.getId())) ||
                (currentDoc.getAuthentication() != null && currentDoc.getAuthentication().contains(authorizingKeyId));
        boolean keyToRemoveExists = currentDoc.getVerificationMethod().stream().anyMatch(vm -> keyIdToRemove.equals(vm.getId()));

        if (!authKeyExists) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "提供的授权密钥ID '" + authorizingKeyId + "' 无效。"));
        }
        if (!keyToRemoveExists) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "要移除的密钥ID '" + keyIdToRemove + "' 在该DID文档中未找到。"));
        }

        if (authorizingKeyId.equals(keyIdToRemove)) {
            // 检查如果移除后是否还有其他认证方法
            long authMethodsCount = currentDoc.getAuthentication() != null ? currentDoc.getAuthentication().size() : 0;
            boolean isLastAuthKey = currentDoc.getAuthentication() != null &&
                    currentDoc.getAuthentication().contains(keyIdToRemove) &&
                    authMethodsCount == 1;
            if (isLastAuthKey) {
                logger.warn("警告：用户尝试使用密钥 '{}' 授权移除其自身，并且这是DID '{}' 的最后一个认证方法。此操作可能导致DID失控。", authorizingKeyId, didToUpdate);
                // 根据策略，可以阻止此操作或允许但发出更强烈的警告
                // return ResponseEntity.badRequest().body(Collections.singletonMap("error", "不能移除最后一个认证密钥，除非有恢复机制。"));
            }
        }

        String challenge = UUID.randomUUID().toString();
        HttpSession session = httpRequest.getSession(true);
        String sessionChallengeKey = "remove_key_challenge_" + didToUpdate + "_" +
                authorizingKeyId.replaceAll("[^a-zA-Z0-9_-]", "_") + "_" +
                keyIdToRemove.replaceAll("[^a-zA-Z0-9_-]", "_");
        session.setAttribute(sessionChallengeKey, challenge);

        Map<String, String> response = new HashMap<>();
        response.put("did", didToUpdate);
        response.put("authorizingKeyId", authorizingKeyId);
        response.put("keyIdToRemove", keyIdToRemove);
        response.put("challenge", challenge);

        logger.info("为DID '{}' 的移除密钥 '{}' 操作 (授权密钥ID: {}) 生成挑战: '{}'", didToUpdate, keyIdToRemove, authorizingKeyId, challenge);
        return ResponseEntity.ok(response);
    }

    /**
     * 阶段2：执行DID文档更新 - 移除验证方法。
     * POST /api/did/update/remove-key/execute
     * 请求体: {@link com.bjut.blockchain.did.dto.DidKeyRemovalRequest}
     */
    @PostMapping("/update/remove-key/execute")
    @Transactional
    public ResponseEntity<Map<String, Object>> executeRemoveKey(@RequestBody DidKeyRemovalRequest removalRequest, HttpServletRequest httpRequest) {
        Map<String, Object> response = new HashMap<>();

        if (removalRequest == null || removalRequest.getDid() == null || removalRequest.getKeyIdToRemove() == null ||
                removalRequest.getAuthorizingKeyId() == null || removalRequest.getChallenge() == null || removalRequest.getSignatureBase64() == null) {
            response.put("success", false); response.put("message", "请求体不完整。");
            return ResponseEntity.badRequest().body(response);
        }

        HttpSession session = httpRequest.getSession(false);
        if (session == null) {
            response.put("success", false); response.put("message", "会话不存在或已过期。");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        String sessionChallengeKey = "remove_key_challenge_" + removalRequest.getDid() + "_" +
                removalRequest.getAuthorizingKeyId().replaceAll("[^a-zA-Z0-9_-]", "_") + "_" +
                removalRequest.getKeyIdToRemove().replaceAll("[^a-zA-Z0-9_-]", "_");
        String serverChallenge = (String) session.getAttribute(sessionChallengeKey);
        session.removeAttribute(sessionChallengeKey);

        if (serverChallenge == null || !serverChallenge.equals(removalRequest.getChallenge())) {
            response.put("success", false); response.put("message", "挑战无效、不匹配或已过期。");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        Map<String, Object> dataToSignMap = new LinkedHashMap<>();
        dataToSignMap.put("operationType", "removeKey");
        dataToSignMap.put("did", removalRequest.getDid());
        dataToSignMap.put("authorizingKeyId", removalRequest.getAuthorizingKeyId());
        dataToSignMap.put("challenge", serverChallenge);
        dataToSignMap.put("keyIdToRemove", removalRequest.getKeyIdToRemove());

        String canonicalPayloadToVerify;
        try {
            canonicalPayloadToVerify = objectMapper.writeValueAsString(dataToSignMap);
        } catch (JsonProcessingException e) {
            response.put("success", false); response.put("message", "内部服务器错误：无法准备验证数据。");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
        logger.debug("为DID '{}' 移除密钥操作的待验证签名数据: {}", removalRequest.getDid(), canonicalPayloadToVerify);

        boolean signatureIsValid = didAuthenticationService.verifyDidControl(
                removalRequest.getDid(),
                canonicalPayloadToVerify,
                removalRequest.getSignatureBase64(),
                removalRequest.getAuthorizingKeyId()
        );

        if (!signatureIsValid) {
            response.put("success", false); response.put("message", "签名验证失败。无法授权此移除密钥操作。");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        try {
            DidDocument updatedDocument = didService.removeVerificationMethodFromDocument(removalRequest.getDid(), removalRequest.getKeyIdToRemove());
            if (updatedDocument != null) {
                boolean actuallyRemoved = updatedDocument.getVerificationMethod().stream()
                        .noneMatch(vm -> removalRequest.getKeyIdToRemove().equals(vm.getId()));
                if (actuallyRemoved) {
                    response.put("success", true);
                    response.put("message", "密钥 '" + removalRequest.getKeyIdToRemove() + "' 已成功从DID文档中移除。");
                    response.put("updatedDidDocument", updatedDocument);
                    return ResponseEntity.ok(response);
                } else {
                    response.put("success", false);
                    response.put("message", "从DID文档移除密钥失败（服务层报告未找到要移除的密钥，或由于业务规则未移除）。");
                    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response); // 或 400 Bad Request
                }
            } else {
                response.put("success", false);
                response.put("message", "从DID文档移除密钥失败（可能是DID不存在）。");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }
        } catch (Exception e) {
            logger.error("执行移除密钥时，DidService操作失败。DID: {}", removalRequest.getDid(), e);
            response.put("success", false);
            response.put("message", "移除密钥时发生内部错误：" + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}
