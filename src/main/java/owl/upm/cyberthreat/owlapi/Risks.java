package owl.upm.cyberthreat.owlapi;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLClassExpression;
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

public class Risks {

	private Map<String, OWLNamedIndividual> riskinstances = new HashMap<String, OWLNamedIndividual>();
	private Map<String, OWLNamedIndividual> priskinstances = new HashMap<String, OWLNamedIndividual>();
	private Map<String, OWLNamedIndividual> rriskinstances = new HashMap<String, OWLNamedIndividual>();
	private double numAmenazas;
	private String riskName;
	private OWLDataFactory dataFactory;
	private OWLOntology o;
	private OWLOntologyManager man;
	private String base;
	private String baseO;
	
	public Risks(Map<String, OWLNamedIndividual> riskinstances, OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base) {
		this.riskinstances = riskinstances;
		this.man = man;
		this.o=o;
		this.dataFactory = dataFactory;
		this.base = base;
		this.baseO = o.getOntologyID().getOntologyIRI().get().toString();

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
	
	public Map<String, OWLNamedIndividual> getPriskinstances(){
		PrefixManager pmDRM = new DefaultPrefixManager(base + "#");
		PrefixManager pm = new DefaultPrefixManager(baseO + "#");
		
		for(Map.Entry<String, OWLNamedIndividual> entry : getRiskinstances().entrySet()) {
			OWLDataProperty type = dataFactory.getOWLDataProperty(":type", pm);
			
			Set<OWLNamedIndividual> prrr = o.getIndividualsInSignature();
			for(OWLNamedIndividual p: prrr) {
				String ptype = obtainDataPropertyValue(p, type, o);
				if(ptype != null && isPotentialRisk(p, o, dataFactory, base) && ptype.equals(entry.getKey())) {
					priskinstances.put(entry.getKey(), p);
				}	
			}

		}
		return priskinstances;
	}
	
	public Map<String, OWLNamedIndividual> getRriskinstances(){
		PrefixManager pmDRM = new DefaultPrefixManager(base + "#");
		PrefixManager pm = new DefaultPrefixManager(baseO + "#");
		
		for(Map.Entry<String, OWLNamedIndividual> entry : getRiskinstances().entrySet()) {
			OWLDataProperty type = dataFactory.getOWLDataProperty(":type", pm);
			
			Set<OWLNamedIndividual> rr = o.getIndividualsInSignature();
			for(OWLNamedIndividual r: rr) {
				String ptype = obtainDataPropertyValue(r, type, o);
				if(ptype != null && isResidualRisk(r, o, dataFactory, base) && ptype.equals(entry.getKey())) {
					rriskinstances.put(entry.getKey(), r);
				}	
			}

		}
		return rriskinstances;
	}
 
	public boolean isPotentialRisk(OWLIndividual individual, OWLOntology o, OWLDataFactory dataFactory, String base_DRM) {
		PrefixManager pmDRM = new DefaultPrefixManager(base_DRM + "#");
		
        boolean result = false;
        OWLClassExpression pr = dataFactory.getOWLClass(":PotentialRisk", pmDRM);

        Set<OWLClassAssertionAxiom> classes = o.getClassAssertionAxioms(individual);
			for (OWLClassAssertionAxiom ax : classes) {
				if (ax.getClassExpression().equals(pr)) {
			             result = true;
			         }
			}
      
		return result;
	}
	
	public String obtainDataPropertyValue(OWLIndividual individual,OWLDataProperty dproperty, OWLOntology o) {
        String result = null;
   
        Set<OWLDataPropertyAssertionAxiom> properties = o.getDataPropertyAssertionAxioms(individual);
			for (OWLDataPropertyAssertionAxiom ax : properties) {
				if (ax.getProperty().equals(dproperty) && ax.getSubject().equals(individual)) {
			             result = ax.getObject().getLiteral().toString();
			         }
			}
        return(result);
    }
	
	public boolean isResidualRisk(OWLIndividual individual, OWLOntology o, OWLDataFactory dataFactory, String base_DRM) {
		PrefixManager pmDRM = new DefaultPrefixManager(base_DRM + "#");
		
        boolean result = false;
        OWLClassExpression rr = dataFactory.getOWLClass(":ResidualRisk", pmDRM);

        Set<OWLClassAssertionAxiom> classes = o.getClassAssertionAxioms(individual);
			for (OWLClassAssertionAxiom ax : classes) {
				if (ax.getClassExpression().equals(rr)) {
			             result = true;
			         }
			}
      
		return result;
	}
	
}
