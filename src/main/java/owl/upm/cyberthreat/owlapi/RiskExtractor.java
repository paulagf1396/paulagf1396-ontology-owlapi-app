package owl.upm.cyberthreat.owlapi;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDataPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLNamedIndividual;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.PrefixManager;

import org.semanticweb.owlapi.util.DefaultPrefixManager;

//CLASE QUE SACA LOS RIESGOS POTENCIALES Y RESIDUALES Y LOS METE EN EL JSON PARA LUEGO SACARLOS Y CALCULARNOS LOS RIESGOS CONTINUOS

public class RiskExtractor {
	
	public static  final String fileDatosPath = "/Users/paulagarcia/eclipse-workspace/cyberthreat.owlapi/owl-files/datos.json";
	public static  final String fileRecommendationsPath = "/Users/paulagarcia/eclipse-workspace/cyberthreat.owlapi/owl-files/recommendations.json";
	private Map<String, OWLNamedIndividual> priskinstances = new HashMap<String, OWLNamedIndividual>() ;
	private Map<String, OWLNamedIndividual> rriskinstances = new HashMap<String, OWLNamedIndividual>();
	private Map<String, OWLNamedIndividual> mriskinstances = new HashMap<String, OWLNamedIndividual>();
	
	public void obtainValues(Risks risks) {
		priskinstances = risks.getPriskinstances();
		rriskinstances = risks.getRriskinstances();
		mriskinstances = risks.getMriskinstances();
		
	}
	
	
	public RiskTotalData infoExtractor(OWLOntologyManager man, OWLOntology o, String base, OWLDataFactory dataFactory, Risks risks) {
		obtainValues(risks);
		PrefixManager pm = new DefaultPrefixManager(base + "#");
		Set<RiskData> riskData = new HashSet<RiskData>();
		Set<RiskManagementData> riskM = new HashSet<RiskManagementData>();
		
		float pRiskTotal=0;
		float rRiskTotal=0;
		double numThreatTotal=0;
		
		for(Map.Entry<String, OWLNamedIndividual> entry : risks.getRiskinstances().entrySet()) {
			String riskName = risks.getRiskName(entry.getValue());
			
			OWLDataProperty numAmenazas = dataFactory.getOWLDataProperty(":namenazas",pm);
			String threatNum = obtainDataPropertyValue(entry.getValue(), numAmenazas, o);
			double num = Double.parseDouble(threatNum);
			
			
			float pRisk = 0;
			for(Map.Entry<String, OWLNamedIndividual> entryPR : priskinstances.entrySet()) {
				if(riskName.equals(entryPR.getKey())) {
					OWLDataProperty pr = dataFactory.getOWLDataProperty(":potentialRisk",pm);
					String p= obtainDataPropertyValue(entryPR.getValue(), pr, o);
					if(p!=null) pRisk=Float.parseFloat(p);
				}
			}
			
			float rRisk = 0;
			for(Map.Entry<String, OWLNamedIndividual> entryRR : rriskinstances.entrySet()) {
				if(riskName.equals(entryRR.getKey())) {
					OWLDataProperty ar = dataFactory.getOWLDataProperty(":actualRisk",pm);
					String a= obtainDataPropertyValue(entryRR.getValue(), ar, o);
					if(a!=null) rRisk=Float.parseFloat(a);
				}
			}
			
			float impact = 0;
			for(Map.Entry<String, OWLNamedIndividual> entryPR : priskinstances.entrySet()) {
				if(riskName.equals(entryPR.getKey())) {
					OWLDataProperty im = dataFactory.getOWLDataProperty(":impact",pm);
					String a= obtainDataPropertyValue(entryPR.getValue(), im, o);
					if(a!=null) impact=Float.parseFloat(a);
				}
			}
			
			float probability = 0;
			for(Map.Entry<String, OWLNamedIndividual> entryPR : priskinstances.entrySet()) {
				if(riskName.equals(entryPR.getKey())) {
					OWLDataProperty pro = dataFactory.getOWLDataProperty(":probability",pm);
					String a= obtainDataPropertyValue(entryPR.getValue(), pro, o);
					if(a!=null) probability=Float.parseFloat(a);
				}
			}
			
			String riesgoaRecomendar="";
			float value = 0;
			String recommendationType="";
			
			for(Map.Entry<String, OWLNamedIndividual> entryMR : mriskinstances.entrySet()) {
				if(riskName.equals(entryMR.getKey())) {
					riesgoaRecomendar = entryMR.getKey();
					OWLDataProperty mvalue = dataFactory.getOWLDataProperty(":drm_value",pm);
					String p= obtainDataPropertyValue(entryMR.getValue(), mvalue, o);
					if(p!=null) value=Float.parseFloat(p);
					OWLDataProperty reco = dataFactory.getOWLDataProperty(":type",pm);
					String t= obtainDataPropertyValue(entryMR.getValue(), reco, o);
					if(t!=null) recommendationType = t;
				}
				
				
				
			}
			RiskManagementData riskMI = new RiskManagementData(value, recommendationType ,riesgoaRecomendar);
			System.out.println("ActualRisk: "+ riskMI.getActualRisk());
			System.out.println("Risk Recommendation: "+ riskMI.getRecommendationType());
			System.out.println("Risk Type: "+ riskMI.getRiesgoARecomendar());
			
			riskM.add(riskMI);
			
			RiskData riskX = new RiskData(riskName, num, pRisk, rRisk, impact, probability);
			riskData.add(riskX);
			
			System.out.println("Risk Name: "+ riskX.getRiskName());
			System.out.println("Risk Amenazas: "+ riskX.getThreatNum());
			System.out.println("Risk Residual: "+ riskX.getrRisk());
			System.out.println("Risk Potential: "+ riskX.getpRisk());
			System.out.println("Risk Impact: "+ riskX.getImpact());
			System.out.println("Risk Probability: "+ riskX.getProbability());
			
				
		}
		
		for(RiskData r: riskData) {
			pRiskTotal = (float) (pRiskTotal + r.getpRisk()*r.getThreatNum());
			rRiskTotal = (float) (rRiskTotal + r.getrRisk()*r.getThreatNum());
			numThreatTotal = numThreatTotal + r.getThreatNum();
		}
		
		if(priskinstances.size()>0) pRiskTotal = (float) (pRiskTotal/numThreatTotal);
		
		if(rriskinstances.size()>0) rRiskTotal = (float) (rRiskTotal/numThreatTotal);
		
		
		String actualDate = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").format(new Date(System.currentTimeMillis()));

		RiskTotalData totalresults = new RiskTotalData (actualDate, pRiskTotal, rRiskTotal, riskData, numThreatTotal,riskM );
		return totalresults;

	}
	

	
	
	public static String obtainDataPropertyValue(OWLIndividual individual,OWLDataProperty dproperty, OWLOntology o) {
        String result = null;
       
        Set<OWLDataPropertyAssertionAxiom> properties = o.getDataPropertyAssertionAxioms(individual);
			for (OWLDataPropertyAssertionAxiom ax : properties) {
				if (ax.getProperty().equals(dproperty) && ax.getSubject().equals(individual)) {
			             result = ax.getObject().getLiteral().toString();
			         }
			}
        return(result);
    }
	
	
	@SuppressWarnings("unchecked")
	public void jsonWriter(RiskTotalData totalresults) throws IOException, ParseException {
			
	
			String[] totaldata = {totalresults.getDate(), ""+totalresults.getpRiskTotal() , ""+totalresults.getrRiskTotal(), ""+totalresults.getNumThreatTotal(), ""+totalresults.getpRiskTotalTimeFunction(), ""+totalresults.getrRiskTotalTimeFunction()};
			Map finalm=new LinkedHashMap();
			Map objm=new LinkedHashMap();
			JSONArray jSONfinal = new JSONArray();
			
			objm.put("Time", totaldata[0]);
			objm.put("Potential Total Risk", totaldata[1]);
			objm.put("Residual Total Risk", totaldata[2]);
			objm.put("Potential Total Risk Continuous", totaldata[4]);
			objm.put("Residual Total Risk Continuous", totaldata[5]);
			objm.put("Threat Total Number", totaldata[3]);


		
			
			JSONArray ja = new JSONArray();
			for(RiskData rd: totalresults.getRiskData()) {
				Map risksOBJm=new LinkedHashMap();
				JSONObject risksOBJ = new JSONObject();
				String[] individualRiskData = {rd.getRiskName(), ""+rd.getpRisk() , ""+rd.getrRisk(), ""+rd.getThreatNum(), ""+rd.getImpact(), ""+rd.getProbability() };
				risksOBJm.put("Risk Name", individualRiskData[0]);
				risksOBJm.put("Potential Risk", individualRiskData[1]);
				risksOBJm.put("Residual Risk", individualRiskData[2]);
				risksOBJm.put("Threat Number", individualRiskData[3]);
				risksOBJm.put("Impact Value", individualRiskData[4]);
				risksOBJm.put("Probability Value", individualRiskData[5]);
				
				ja.add(risksOBJm);
			}
			objm.put("Risks",ja);
			
			
			JSONArray ja2 = new JSONArray();
			for(RiskManagementData rm: totalresults.getRiskM()) {
				Map risksOBJm=new LinkedHashMap();
				JSONObject risksOBJ = new JSONObject();
				String[] individualRiskData = {rm.getRiesgoARecomendar(), rm.getRecommendationType() , ""+rm.getActualRisk() };
				risksOBJm.put("Risk", individualRiskData[0]);
				risksOBJm.put("Recommendation Strategy", individualRiskData[1]);
				risksOBJm.put("Risk Value", individualRiskData[2]);

				
				ja2.add(risksOBJm);
			}
			objm.put("Strategies",ja2);
			jSONfinal.add(objm);
			
			System.out.println("Vas a crearte el array \n");
		
		try{
			
			
			File file = new File(fileDatosPath);
			if(!file.exists()) {
				file.createNewFile();
			}
			BufferedReader br = new BufferedReader(new FileReader(fileDatosPath));
			String line = br.readLine();
			
			if(line == null || line.isEmpty()) {
				StringWriter out = new StringWriter();
				JSONValue.writeJSONString(jSONfinal, out);
				String jsonText = out.toString();
				br.close();
				FileWriter fileWriter = new FileWriter(fileDatosPath);

				fileWriter.write(jsonText);
				fileWriter.flush();
				fileWriter.close();
				return;
				
			}
			
			if(line.endsWith("}]}]")) {
				StringWriter out = new StringWriter();
				JSONValue.writeJSONString(objm, out);
				String jsonText = out.toString();
				String borrarCorchete = line.replace("}]}]", "}]},"+jsonText+"]");
				br.close();
				FileWriter fileWriter = new FileWriter(fileDatosPath);
				
				fileWriter.write(borrarCorchete);
				fileWriter.flush();
				fileWriter.close();
				return;
			}
			//y si existe una con el mismo time SE ACTUALIZA Y SE CAMBIA---------------------------------------------
			
			
			//FileWriter fileWriter = new FileWriter(fileDatosPath);
	        //StringWriter out = new StringWriter();
			//JSONValue.writeJSONString(jSONfinal, out);
			//String jsonText = out.toString();	
			
		
			
	
			
		}catch(Exception ex){
			System.out.println("Error: "+ex.toString());
		}
		finally{
			
			
		}
	}
	
	
	public void jsonWriterRecommendations(RiskTotalData riskM) throws IOException, ParseException {
		
		
		String[] totaldata = {riskM.getDate(), ""+riskM.getpRiskTotal() , ""+riskM.getrRiskTotal(), ""+riskM.getNumThreatTotal(), ""+riskM.getpRiskTotalTimeFunction(), ""+riskM.getrRiskTotalTimeFunction()};
		Map finalm=new LinkedHashMap();
		Map objm=new LinkedHashMap();
		JSONArray jSONfinal = new JSONArray();
		
		objm.put("Time", totaldata[0]);
		JSONArray ja = new JSONArray();
		for(RiskManagementData rm: riskM.getRiskM()) {
			Map risksOBJm=new LinkedHashMap();
			JSONObject risksOBJ = new JSONObject();
			String[] individualRiskData = {rm.getRiesgoARecomendar(), rm.getRecommendationType() , ""+rm.getActualRisk() };
			risksOBJm.put("Risk", individualRiskData[0]);
			risksOBJm.put("Recommendation Strategy", individualRiskData[1]);
			risksOBJm.put("Risk Value", individualRiskData[2]);

			
			ja.add(risksOBJm);
		}
		objm.put("Risks",ja);
		jSONfinal.add(objm);
		
		System.out.println("Vas a crearte el array \n");
	
	try{
		
		
		File file = new File(fileRecommendationsPath);
		if(!file.exists()) {
			file.createNewFile();
		}
		BufferedReader br = new BufferedReader(new FileReader(fileRecommendationsPath));
		String line = br.readLine();
		
		if(line == null || line.isEmpty()) {
			StringWriter out = new StringWriter();
			JSONValue.writeJSONString(jSONfinal, out);
			String jsonText = out.toString();
			br.close();
			FileWriter fileWriter = new FileWriter(fileRecommendationsPath);

			fileWriter.write(jsonText);
			fileWriter.flush();
			fileWriter.close();
			return;
			
		}
		
		if(line.endsWith("}]}]")) {
			StringWriter out = new StringWriter();
			JSONValue.writeJSONString(objm, out);
			String jsonText = out.toString();
			String borrarCorchete = line.replace("}]}]", "}]},"+jsonText+"]");
			br.close();
			FileWriter fileWriter = new FileWriter(fileRecommendationsPath);
			
			fileWriter.write(borrarCorchete);
			fileWriter.flush();
			fileWriter.close();
			return;
		}
		//y si existe una con el mismo time SE ACTUALIZA Y SE CAMBIA---------------------------------------------
		
		
		//FileWriter fileWriter = new FileWriter(fileDatosPath);
        //StringWriter out = new StringWriter();
		//JSONValue.writeJSONString(jSONfinal, out);
		//String jsonText = out.toString();	
		
	
		

		
	}catch(Exception ex){
		System.out.println("Error: "+ex.toString());
	}
	finally{
		
		
	}
}
	
	@SuppressWarnings("unchecked")
	public JSONArray updatejsonfile(File filename, RiskTotalData totalresults) throws IOException, ParseException{
		
		

		
		
		JSONArray dataList = new JSONArray();

			System.out.println("Hola estas en coger datos");
			JSONParser jsonParser = new JSONParser();
			FileReader reader = new FileReader(filename);
			Object obj = jsonParser.parse(reader);
			dataList = (JSONArray) obj;
	        System.out.println(dataList);	
	
		
		return dataList;
		
	}
	
}
