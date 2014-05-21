<?php
namespace AP\ApLdapAuth\Domain\Repository;

use AP\ApLdap\Exception\LDAPException,
	TYPO3\CMS\Core\Utility\GeneralUtility;
use AP\ApLdapAuth\Utility\LDAPConfigUtility;

/**
 * Repository for LDAP frontend users
 *
 * @package TYPO3
 * @subpackage tx_apldapauth
 * @author Alexander Pankow <info@alexander-pankow.de>
 */
class LDAPFEUserRepository extends \AP\ApLdapAuth\Persistence\LdapRepository {

	/**
	 * Check if user exists
	 *
	 * @param $username
	 * @param $password
	 * @return array|bool
	 */
	public function checkUser($username, $password) {
		$result = false;
		foreach ($this->getLDAPConnections() as $ldapConnection) {
			$filter = str_replace('<username>', $username, $ldapConnection->getConfig()->getFeUsersFilter());
			$baseDn = $ldapConnection->getConfig()->getFeUsersBaseDn();
			$search = $ldapConnection->search($baseDn, $filter)->getFirstEntry();

			// try to bind as found user
			if ($search->countEntries() > 0) {
				$entry = $search->getLastEntry();
				$ldapUser = array();
				foreach ($search->getAttributes() as $attribute => $values) {
					if ($values['count'] <= 0)
						continue;

					$imageField = LDAPConfigUtility::getImageAttribute($ldapConnection->getConfig()->getFeUsersMapping());
					foreach ($values as $key => $value) {
						if (empty($imageField) || $attribute != $imageField)
							$ldapUser[$attribute][$key] = $value;
						else if (!isset($ldapUser[$attribute]))
							$ldapUser[$attribute] = $search->getBinaryValues($attribute);
					}
				}
				$ldapUser['dn'] = $username = $search->getDN($entry);
				try {
					if ($ldapConnection->bind($username, $password)) {
						$result = array(
							'ldapUser' => $ldapUser,
							'config' => $ldapConnection->getConfig()
						);
					}
				} catch (LDAPException $e) {
					GeneralUtility::sysLog($e->getMessage(), 'ap_ldap_auth', GeneralUtility::SYSLOG_SEVERITY_ERROR);
				}
			}
		}

		return $result;
	}
}
