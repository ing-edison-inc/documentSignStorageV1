// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title DocumentRegistry
 * @dev Registro y verificación criptográfica de documentos firmados
 * Permite almacenar hashes de documentos junto con la firma del firmante, y posteriormente verificar la autenticidad de la firma.
 * El contrato utiliza la biblioteca ECDSA de OpenZeppelin para la recuperación de la dirección del firmante a partir de la firma y el hash del documento.
 * @author Ing.edison Salinas Camacho
 */
contract DocumentRegistry {
    using ECDSA for bytes32;

    struct Document {
        bytes32 hash;
        uint256 registeredAt;
        address signer;
        bytes signature;
    }

    mapping(bytes32 => Document) private documents;
    bytes32[] private documentHashes;

    error DocumentAlreadyExists();
    error DocumentNotFound();
    error EmptySignature();
    error InvalidSignature();
    error IndexOutOfBounds();

    event DocumentStored(bytes32 indexed hash, address indexed signer, uint256 registeredAt);

    event DocumentVerified(bytes32 indexed hash, address indexed recoveredSigner, bool isValid);

    modifier documentNotExists(bytes32 _hash) {
        _documentNotExists(_hash);
        _;
    }

    modifier documentExists(bytes32 _hash) {
        _documentExists(_hash);
        _;
    }

    function _documentNotExists(bytes32 _hash) internal view {
        if (documents[_hash].signer != address(0)) revert DocumentAlreadyExists();
    }

    function _documentExists(bytes32 _hash) internal view {
        if (documents[_hash].signer == address(0)) revert DocumentNotFound();
    }

    /**
     * @dev Registra un documento verificando criptográficamente la firma
     * @param _hash Hash del documento
     * @param _signature Firma del hash del documento
     */
    function storeDocumentHash(bytes32 _hash, bytes calldata _signature) external documentNotExists(_hash) {
        if (_signature.length == 0) revert EmptySignature();

        address recoveredSigner = _recoverSigner(_hash, _signature);

        if (recoveredSigner == address(0)) revert InvalidSignature();

        documents[_hash] =
            Document({hash: _hash, registeredAt: block.timestamp, signer: recoveredSigner, signature: _signature});

        documentHashes.push(_hash);

        emit DocumentStored(_hash, recoveredSigner, block.timestamp);
    }

    /**
     * @dev Verifica si la firma suministrada corresponde al documento almacenado
     * @param _hash Hash del documento
     * @param _signature Firma a verificar
     * @return isValid true si la firma corresponde al firmante almacenado
     * @return recoveredSigner dirección recuperada desde la firma
     */
    function verifyDocument(bytes32 _hash, bytes calldata _signature)
        external
        view
        documentExists(_hash)
        returns (bool isValid, address recoveredSigner)
    {
        if (_signature.length == 0) revert EmptySignature();

        recoveredSigner = _recoverSigner(_hash, _signature);
        isValid = (recoveredSigner == documents[_hash].signer);
    }

    /**
     * @dev Devuelve la información completa del documento
     */
    function getDocumentInfo(bytes32 _hash) external view documentExists(_hash) returns (Document memory) {
        return documents[_hash];
    }

    /**
     * @dev Devuelve la firma almacenada del documento
     */
    function getDocumentSignature(bytes32 _hash) external view documentExists(_hash) returns (bytes memory) {
        return documents[_hash].signature;
    }

    /**
     * @dev Indica si un documento ya fue registrado
     */
    function isDocumentStored(bytes32 _hash) external view returns (bool) {
        return documents[_hash].signer != address(0);
    }

    /**
     * @dev Cantidad total de documentos registrados
     */
    function getDocumentCount() external view returns (uint256) {
        return documentHashes.length;
    }

    /**
     * @dev Obtiene un hash por índice
     */
    function getDocumentHashByIndex(uint256 _index) external view returns (bytes32) {
        if (_index >= documentHashes.length) revert IndexOutOfBounds();
        return documentHashes[_index];
    }

    /**
     * @dev Recupera el firmante real desde el hash del documento y la firma
     */
    function _recoverSigner(bytes32 _hash, bytes memory _signature) internal pure returns (address) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(_hash);
        return ECDSA.recover(ethSignedMessageHash, _signature);
    }
}
