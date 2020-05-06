/*package owl.upm.cyberthreat.owlapi;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.semanticweb.owlapi.model.AxiomType;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLClassExpression;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDataPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLDataPropertyRangeAxiom;
import org.semanticweb.owlapi.model.OWLDataRange;
import org.semanticweb.owlapi.model.OWLDatatype;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLLiteral;
import org.semanticweb.owlapi.model.OWLNamedIndividual;
import org.semanticweb.owlapi.model.OWLObjectProperty;
import org.semanticweb.owlapi.model.OWLObjectPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.util.DefaultPrefixManager;
import org.semanticweb.owlapi.vocab.OWL2Datatype;

public class ThreatControl {

	
	public OWLOntology o;
	public OWLOntologyManager man;
	public OWLDataFactory dataFactory;
	public String baseO;
	public DRM drm;
	
	public static double numeroAmenazasPorRiesgo[];
	
	
	
	public ThreatControl(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base) {
		this.o=o;
		this.dataFactory = dataFactory;
		this.man = man;
		this.baseO = base;
		drm = new DRM(dataFactory, man, base);
		numeroAmenazasPorRiesgo = new double[drm.risk_names.length];
	}
	
	public void initialization() {
		for(int i=0; i< numeroAmenazasPorRiesgo.length-1; i++ ) {
			numeroAmenazasPorRiesgo[i] =0.0;
		}
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
	public Risks nAmenazasConfiguration(Set<OWLNamedIndividual> amenazasExistentes, OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLReasoner reasoner) throws OWLOntologyStorageException {
		Map<String, OWLNamedIndividual> riskinstances = null;
		PrefixManager pm = new DefaultPrefixManager(drm.base + "#");
		PrefixManager pmO = new DefaultPrefixManager(baseO + "#");
		
		for(OWLNamedIndividual t: amenazasExistentes) {
			OWLDataProperty numType = dataFactory.getOWLDataProperty(":numType", pmO);
			String num = obtainDataPropertyValue(t, numType, o);
			int numero=-1;
			if(StringUtils.isNumeric(num)) {
				numero = Integer.parseInt(num);
			}
			
			switch(numero) {
			case 1:
				numeroAmenazasPorRiesgo[1]++;
				
				break;
			case 4:
				numeroAmenazasPorRiesgo[4]++;
				break;
			case 5:
				numeroAmenazasPorRiesgo[5]++;
				break;
	
			default:
				break;
    		}	
			
		}
		Set<OWLNamedIndividual> instances = o.getIndividualsInSignature();
		for(OWLNamedIndividual k: instances) {
			int type;
			type = isRiskType(k, o, dataFactory, reasoner, drm.base);
			if(type!=-1) {	
				
				OWLDataProperty property = dataFactory.getOWLDataProperty(":namenazas",pmO);
				createDataProperty(o, man, dataFactory, baseO, k, property, numeroAmenazasPorRiesgo[type]);
				for(int i=0; i<instances.size();i++) {
					riskinstances.put("", k);
				}
				
			}
			
		}
		Risks risks = new Risks(riskinstances, o, man , dataFactory, this.baseO);
		man.saveOntology(o);
		return risks;
		
	}
	//Crear Data Properties
	public void createDataProperty(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLIndividual object, OWLDataProperty dproperty, Double value) {

		if (dproperty!=null &&  object!=null && value!=null) {
			Set<OWLDataPropertyAssertionAxiom> properties = o.getDataPropertyAssertionAxioms(object);
			for (OWLDataPropertyAssertionAxiom ax : properties) {
				if (ax.getProperty().equals(dproperty) && ax.getSubject().equals(object)) {
					man.removeAxiom(o, ax);
				}	
			}
			
			OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, object, value);
			man.addAxiom(o, dAxiom);
		}else {
			System.out.println("Not properly data to create Data Property");
		}
		
		
	}
	
	public int isRiskType(OWLIndividual individual, OWLOntology o, OWLDataFactory dataFactory, OWLReasoner reasoner, String base_DRM) {
		PrefixManager pmDRM = new DefaultPrefixManager(base_DRM + "#");
        int result=-1;
        for(int i = 0; i < drm.risk_names.length; i++) {
        	
        	OWLClassExpression pr = dataFactory.getOWLClass(":"+drm.risk_names[i], pmDRM);

            Set<OWLClassAssertionAxiom> classes = o.getClassAssertionAxioms(individual);
    			for (OWLClassAssertionAxiom ax : classes) {
    				if (ax.getClassExpression().equals(pr)) {
    			             result = i;
    			    }
    			}  
        }
		return result;
	}

	
}*/
