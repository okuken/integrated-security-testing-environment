package okuken.iste.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class BurpUtilTest {

	@Test
	void extractBurpSuiteProjectNameFromFrameTitle_pro_update_stable() {
		assertEquals("myprj", BurpUtil.extractBurpSuiteProjectNameFromFrameTitle(
					"Burp Suite Professional v2021.3.1 - myprj - licensed to Hoge. [99 user license]"));
	}

	@Test
	void extractBurpSuiteProjectNameFromFrameTitle_pro_update_earlyAdopter() {
		assertEquals("myprj", BurpUtil.extractBurpSuiteProjectNameFromFrameTitle(
					"Burp Suite Professional v2021.3.1-6584 (Early Adopter) - myprj - licensed to Hoge. [99 user license]"));
	}

	@Test
	void extractBurpSuiteProjectNameFromFrameTitle_pro_pjname_hyphen() {
		assertEquals("my - prj - 1", BurpUtil.extractBurpSuiteProjectNameFromFrameTitle(
					"Burp Suite Professional v2021.3.1 - my - prj - 1 - licensed to Hoge. [99 user license]"));
	}

	@Test
	void extractBurpSuiteProjectNameFromFrameTitle_pro_temporary() {
		assertNull(BurpUtil.extractBurpSuiteProjectNameFromFrameTitle(
					"Burp Suite Professional v2021.3.1 - Temporary Project - licensed to Hoge. [99 user license]"));
	}

	@Test
	void extractBurpSuiteProjectNameFromFrameTitle_community() {
		assertNull(BurpUtil.extractBurpSuiteProjectNameFromFrameTitle(
					"Burp Suite Community Edition v2021.3.1 - Temporary Project"));
	}

}
