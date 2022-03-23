bool CCryptoKeyStore::Unlock(const CKeyingMaterial& vMasterKeyIn)
{
  {
    LOCK(cs_KeyStore);
    if (!SetCrypted())
      return false;

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
    for (; mi != mapCryptedKeys.end(); ++mi)
    {
      const CPubKey &vchPubKey = (*mi).second.first;
      const std::vector<unsigned char> &vchCryptedSecret =
        (*mi).second.second;
      CKeyingMaterial vchSecret;
      if(!DecryptSecret(vMasterKeyIn, vchCryptedSecret,
                        vchPubKey.GetHash(), vchSecret))
          return false;
      if (vchSecret.size() != 32)
          return false;
      CKey key;
      key.Set(vchSecret.begin(), vchSecret.end(),
              vchPubKey.IsCompressed());
      if (key.GetPubKey() == vchPubKey)
          break;
      return false;
    }
    vMasterKey = vMasterKeyIn;
  }
  NotifyStatusChanged(this);
  return true;
}
