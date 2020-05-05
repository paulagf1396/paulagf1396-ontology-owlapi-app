package owl.upm.cyberthreat.owlapi;

import java.util.Map;
import java.util.Set;

import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLClassExpression;
import org.semanticweb.owlapi.model.OWLNamedIndividual;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.util.DefaultPrefixManager;

public class Risks {

	private Map<String, OWLNamedIndividual> riskinstances;
	private double numAmenazas;
	private String riskName;
	
	public Risks(Map<String, OWLNamedIndividual> riskinstances) {
		this.riskinstances = riskinstances;

	}
	public double getNumAmenazas() {
		
		return numAmenazas;
	}

	public void setNumAmenazas(double numAmenazas) {
		this.numAmenazas = numAmenazas;
	}

	public String getRiskName(OWLNamedIndividual ind) {
		riskName ="Error-No existe";
		for(Map.Entry<String, OWLNamedIndividual> entry : getRiskinstances().entrySet()) {
			if(entry.getValue().equals(ind)) {
				riskName = entry.getKey();
			}
		}
		return riskName;
	}

	public void setRiskName(String riskName) {
		this.riskName = riskName;
	}

	public Map<String, OWLNamedIndividual> getRiskinstances() {
		return riskinstances;
	}

	public void setRiskinstances(Map<String, OWLNamedIndividual> riskinstances) {
		this.riskinstances = riskinstances;
	}
	
}
