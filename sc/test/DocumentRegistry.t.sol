// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DocumentRegistry} from "../src/DocumentRegistry.sol";
import {MessageHashUtils} from "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

contract DocumentRegistryTest is Test {
    DocumentRegistry public documentRegistry;

    address public user1;
    address public user2;

    uint256 public user1PrivateKey;
    uint256 public user2PrivateKey;

    function setUp() public {
        user1PrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        user2PrivateKey = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890;

        user1 = vm.addr(user1PrivateKey);
        user2 = vm.addr(user2PrivateKey);

        documentRegistry = new DocumentRegistry();
    }

    function _signDocumentHash(uint256 privateKey, bytes32 documentHash) internal pure returns (bytes memory) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(documentHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    function testStoreDocumentHash() public {
        bytes32 documentHash = keccak256("test document content");
        bytes memory signature = _signDocumentHash(user1PrivateKey, documentHash);

        uint256 expectedTimestamp = block.timestamp;

        documentRegistry.storeDocumentHash(documentHash, signature);

        assertTrue(documentRegistry.isDocumentStored(documentHash));

        DocumentRegistry.Document memory doc = documentRegistry.getDocumentInfo(documentHash);

        assertEq(doc.hash, documentHash);
        assertEq(doc.signer, user1);
        assertEq(doc.registeredAt, expectedTimestamp);
        assertEq(doc.signature, signature);
    }

    function testVerifyDocumentValidSignature() public {
        bytes32 documentHash = keccak256("test document content");
        bytes memory signature = _signDocumentHash(user1PrivateKey, documentHash);

        documentRegistry.storeDocumentHash(documentHash, signature);

        (bool isValid, address recoveredSigner) = documentRegistry.verifyDocument(documentHash, signature);

        assertTrue(isValid);
        assertEq(recoveredSigner, user1);
    }

    function testVerifyDocumentInvalidSignatureFromAnotherUser() public {
        bytes32 documentHash = keccak256("test document content");

        bytes memory validSignature = _signDocumentHash(user1PrivateKey, documentHash);
        bytes memory wrongSignature = _signDocumentHash(user2PrivateKey, documentHash);

        documentRegistry.storeDocumentHash(documentHash, validSignature);

        (bool isValid, address recoveredSigner) = documentRegistry.verifyDocument(documentHash, wrongSignature);

        assertFalse(isValid);
        assertEq(recoveredSigner, user2);
    }

    function testGetDocumentSignature() public {
        bytes32 documentHash = keccak256("test document content");
        bytes memory signature = _signDocumentHash(user1PrivateKey, documentHash);

        documentRegistry.storeDocumentHash(documentHash, signature);

        bytes memory retrievedSignature = documentRegistry.getDocumentSignature(documentHash);
        assertEq(retrievedSignature, signature);
    }

    function testGetDocumentCount() public {
        assertEq(documentRegistry.getDocumentCount(), 0);

        bytes32 documentHash1 = keccak256("document 1");
        bytes32 documentHash2 = keccak256("document 2");

        bytes memory signature1 = _signDocumentHash(user1PrivateKey, documentHash1);
        bytes memory signature2 = _signDocumentHash(user2PrivateKey, documentHash2);

        documentRegistry.storeDocumentHash(documentHash1, signature1);
        assertEq(documentRegistry.getDocumentCount(), 1);

        documentRegistry.storeDocumentHash(documentHash2, signature2);
        assertEq(documentRegistry.getDocumentCount(), 2);
    }

    function testGetDocumentHashByIndex() public {
        bytes32 documentHash1 = keccak256("document 1");
        bytes32 documentHash2 = keccak256("document 2");

        bytes memory signature1 = _signDocumentHash(user1PrivateKey, documentHash1);
        bytes memory signature2 = _signDocumentHash(user2PrivateKey, documentHash2);

        documentRegistry.storeDocumentHash(documentHash1, signature1);
        documentRegistry.storeDocumentHash(documentHash2, signature2);

        assertEq(documentRegistry.getDocumentHashByIndex(0), documentHash1);
        assertEq(documentRegistry.getDocumentHashByIndex(1), documentHash2);
    }

    function testRevertStoreDuplicateDocument() public {
        bytes32 documentHash = keccak256("test document content");
        bytes memory signature = _signDocumentHash(user1PrivateKey, documentHash);

        documentRegistry.storeDocumentHash(documentHash, signature);

        vm.expectRevert(DocumentRegistry.DocumentAlreadyExists.selector);
        documentRegistry.storeDocumentHash(documentHash, signature);
    }

    function testRevertGetNonExistentDocument() public {
        bytes32 documentHash = keccak256("non-existent document");

        vm.expectRevert(DocumentRegistry.DocumentNotFound.selector);
        documentRegistry.getDocumentInfo(documentHash);
    }

    function testRevertGetNonExistentSignature() public {
        bytes32 documentHash = keccak256("non-existent document");

        vm.expectRevert(DocumentRegistry.DocumentNotFound.selector);
        documentRegistry.getDocumentSignature(documentHash);
    }

    function testRevertGetHashByIndexOutOfBounds() public {
        vm.expectRevert(DocumentRegistry.IndexOutOfBounds.selector);
        documentRegistry.getDocumentHashByIndex(0);
    }

    function testRevertEmptySignature() public {
        bytes32 documentHash = keccak256("test document content");
        bytes memory emptySignature = "";

        vm.expectRevert(DocumentRegistry.EmptySignature.selector);
        documentRegistry.storeDocumentHash(documentHash, emptySignature);
    }

    function testMultipleUsersStoreDocuments() public {
        bytes32 documentHash1 = keccak256("user1 document");
        bytes32 documentHash2 = keccak256("user2 document");

        bytes memory signature1 = _signDocumentHash(user1PrivateKey, documentHash1);
        bytes memory signature2 = _signDocumentHash(user2PrivateKey, documentHash2);

        documentRegistry.storeDocumentHash(documentHash1, signature1);
        documentRegistry.storeDocumentHash(documentHash2, signature2);

        assertTrue(documentRegistry.isDocumentStored(documentHash1));
        assertTrue(documentRegistry.isDocumentStored(documentHash2));
        assertEq(documentRegistry.getDocumentCount(), 2);

        (bool valid1, address signer1) = documentRegistry.verifyDocument(documentHash1, signature1);
        (bool valid2, address signer2) = documentRegistry.verifyDocument(documentHash2, signature2);

        assertTrue(valid1);
        assertTrue(valid2);
        assertEq(signer1, user1);
        assertEq(signer2, user2);
    }

    function testInvalidSignatureForAlteredHash() public {
        bytes32 originalHash = keccak256("original document");
        bytes32 alteredHash = keccak256("altered document");

        bytes memory signature = _signDocumentHash(user1PrivateKey, originalHash);

        documentRegistry.storeDocumentHash(originalHash, signature);

        vm.expectRevert(DocumentRegistry.DocumentNotFound.selector);
        documentRegistry.verifyDocument(alteredHash, signature);
    }
}
