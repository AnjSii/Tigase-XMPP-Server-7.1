package tigase.auth.impl;

import java.util.Map;

import tigase.auth.DomainAware;
import tigase.auth.PluginSettingsAware;

public class ShopCertificateCallbackHandler extends AuthRepoPlainCallbackHandler implements DomainAware, PluginSettingsAware {

	@Override
	public void setPluginSettings(Map<String, Object> settings) {

	}
}
