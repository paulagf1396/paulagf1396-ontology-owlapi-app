package owl.upm.cyberthreat.owlapi;


import java.io.FileNotFoundException;
import java.io.FileWriter;
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
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDataPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLNamedIndividual;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.PrefixManager;

import org.semanticweb.owlapi.util.DefaultPrefixManager;


public class RiskExtractor {
	
	public static  final String fileDatosPath = "/Users/paulagarcia/eclipse-workspace/cyberthreat.owlapi/owl-files/datos.json";
	private Map<String, OWLNamedIndividual> priskinstances = new HashMap<String, OWLNamedIndividual>() ;
	private Map<String, OWLNamedIndividual> rriskinstances = new HashMap<String, OWLNamedIndividual>();
	
	public void obtainValues(Risks risks) {
		priskinstances = risks.getPriskinstances();
		rriskinstances = risks.getRriskinstances();
	}
	
	public RiskTotalData infoExtractor(OWLOntologyManager man, OWLOntology o, String base, OWLDataFactory dataFactory, Risks risks) {
		obtainValues(risks);
		PrefixManager pm = new DefaultPrefixManager(base + "#");
		Set<RiskData> riskData = new HashSet<RiskData>();
		
		float pRiskTotal=0;
		float rRiskTotal=0;
		
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
			
			
			
			RiskData riskX = new RiskData(riskName, num, pRisk, rRisk);
			riskData.add(riskX);
			
			System.out.println("Risk Name: "+ riskX.getRiskName());
			System.out.println("Risk Amenazas: "+ riskX.getThreatNum());
			System.out.println("Risk Residual: "+ riskX.getrRisk());
			System.out.println("Risk Potential: "+ riskX.getpRisk());
			
				
		}
		
		for(RiskData r: riskData) {
			pRiskTotal = pRiskTotal + r.getpRisk();
			rRiskTotal = rRiskTotal + r.getrRisk();
		}
		
		if(priskinstances.size()>0) pRiskTotal = pRiskTotal/priskinstances.size();
		
		if(rriskinstances.size()>0) rRiskTotal = rRiskTotal/rriskinstances.size();
		
		
		String actualDate = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").format(new Date(System.currentTimeMillis()));

		RiskTotalData totalresults = new RiskTotalData (actualDate, pRiskTotal, rRiskTotal, riskData);
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
	public void jsonWriter(RiskTotalData totalresults) throws FileNotFoundException {
		String[] totaldata = {totalresults.getDate(), ""+totalresults.getpRiskTotal() , ""+totalresults.getrRiskTotal() };
		Map finalm=new LinkedHashMap();
		Map objm=new LinkedHashMap();
		JSONArray jSONfinal = new JSONArray();
		
		objm.put("Time", totaldata[0]);
		objm.put("Potential Total Risk", totaldata[1]);
		objm.put("Residual Total Risk", totaldata[2]);
	
		
		JSONArray ja = new JSONArray();
		for(RiskData rd: totalresults.getRiskData()) {
			Map risksOBJm=new LinkedHashMap();
			JSONObject risksOBJ = new JSONObject();
			String[] individualRiskData = {rd.getRiskName(), ""+rd.getpRisk() , ""+rd.getrRisk(), ""+rd.getThreatNum() };
			risksOBJm.put("Risk Name", individualRiskData[0]);
			risksOBJm.put("Potential Risk", individualRiskData[1]);
			risksOBJm.put("Residual Risk", individualRiskData[2]);
			risksOBJm.put("Threat Number", individualRiskData[3]);
			
			ja.add(risksOBJm);
		}
		objm.put("Risks",ja);
		jSONfinal.add(objm);
		
		
		try{
			FileWriter file = new FileWriter(fileDatosPath);
			StringWriter out = new StringWriter();

			JSONValue.writeJSONString(jSONfinal, out);
			String jsonText = out.toString();
			file.write(jsonText);
			file.flush();
			file.close();
			
			
		}catch(Exception ex){
			System.out.println("Error: "+ex.toString());
		}
		finally{
			System.out.print(objm);
		}
	}
	
}
