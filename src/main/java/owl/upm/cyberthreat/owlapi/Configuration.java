package owl.upm.cyberthreat.owlapi;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Properties;

public class Configuration {
	

	public static float umbral;
	public static float intervalo;
	public static double penalizationValue;
	
	public static  final String configFilePath = "/Users/paulagarcia/eclipse-workspace/cyberthreat.owlapi/owl-files/config.txt";
	
	public static HashMap<String, String> getPath() {
		Properties prop = new Properties();  
		InputStream is = null;
		
		try {
			is = new FileInputStream(configFilePath);
			prop.load(is);
		} catch(IOException e) {
			System.out.println(e.toString());
		}
		
		HashMap<String, String> configValues = new HashMap<String, String>();
		configValues.put("anomaliesSVConfig", prop.getProperty("ANOMALIES.SV.CONFIG"));
		configValues.put("ficheroJSONSensores", prop.getProperty("ANOMALIES.BBDD.CONFIG"));
		configValues.put("ficheroJSONSTIX", prop.getProperty("STIX.ELEMENTS.CONFIG"));
		configValues.put("riskConfig", prop.getProperty("RISK.CALCULATION"));
		configValues.put("ficheroAssets", prop.getProperty("ASSETS.CONFIG"));
		configValues.put("ficheroAssetValuation", prop.getProperty("ASSET.VALUATION"));


		
		return configValues;
	}
	
	public static void getUmbral() {
		Properties prop = new Properties();  
		InputStream is = null;
		
		try {
			is = new FileInputStream(getPath().get("anomaliesSVConfig"));
			prop.load(is);
		} catch(IOException e) {
			System.out.println(e.toString());
		}

			umbral = Float.parseFloat(prop.getProperty("SUSPICIOUS.VALUE.UMBRAL"));
			
	}
	
	public static void getIntervalo() {
		Properties prop = new Properties();  
		InputStream is = null;
		
		try {
			is = new FileInputStream(getPath().get("anomaliesSVConfig"));
			prop.load(is);
		} catch(IOException e) {
			System.out.println(e.toString());
		}

			intervalo = Float.parseFloat(prop.getProperty("SUSPICIOUS.VALUE.INTERVALO").replace(" ", ""));
			
	}
	public static void getPenalizationValue() {
		Properties prop = new Properties();  
		InputStream is = null;
		
		try {
			is = new FileInputStream(getPath().get("riskConfig"));
			prop.load(is);
		} catch(IOException e) {
			System.out.println(e.toString());
		}

			penalizationValue = Float.parseFloat(prop.getProperty("RISK.PENALIZATION.VALUE").replace(" ", ""));
			
	}
	
	public static void runConfiguration() {
		getPath();
		getUmbral();
		getIntervalo();
		getPenalizationValue();
	}

	
}
