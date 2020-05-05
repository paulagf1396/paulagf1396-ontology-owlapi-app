package owl.upm.cyberthreat.owlapi;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDataPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLNamedIndividual;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.util.DefaultPrefixManager;

public class RiskExtractor {
	
	
	
	public RiskTotalData infoExtractor(OWLOntologyManager man, OWLOntology o, String base, OWLDataFactory dataFactory, Risks risks) {
		PrefixManager pm = new DefaultPrefixManager(base + "#");
		Set<RiskData> riskData = new HashSet<RiskData>();
		
		float pRiskTotal=0;
		float rRiskTotal=0;;
		
		for(Map.Entry<String, OWLNamedIndividual> entry : risks.getRiskinstances().entrySet()) {
			String riskName = risks.getRiskName(entry.getValue());
			
			OWLDataProperty numAmenazas = dataFactory.getOWLDataProperty(":namenazas",pm);
			String threatNum = obtainDataPropertyValue(entry.getValue(), numAmenazas, o);
			double num = Double.parseDouble(threatNum);
			
			OWLDataProperty pr = dataFactory.getOWLDataProperty(":potentialRisk",pm);
			String p= obtainDataPropertyValue(entry.getValue(), pr, o);
			float pRisk = 0;
			if(p!=null)Float.parseFloat(p);
			
			OWLDataProperty ar = dataFactory.getOWLDataProperty(":actualRisk",pm);
			String r = obtainDataPropertyValue(entry.getValue(), ar, o);
			float rRisk = 0;
			if(r!=null) rRisk=Float.parseFloat(r);
			
			RiskData riskX = new RiskData(riskName, num, pRisk, rRisk);
			riskData.add(riskX);
			pRiskTotal = pRiskTotal +pRisk;
			rRiskTotal = rRiskTotal +rRisk;
				
		}
		
	
		
		
		String actualDate = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date(System.currentTimeMillis()));

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

}
