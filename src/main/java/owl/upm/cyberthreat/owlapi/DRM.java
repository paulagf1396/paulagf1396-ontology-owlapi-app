package owl.upm.cyberthreat.owlapi;

import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.util.DefaultPrefixManager;

public class DRM {
	
			//Different Classes from DRM in the Ontology
			private OWLDataFactory dataFactory;
			private OWLOntologyManager man;
			public String base;
			public static OWLClass asset;
			public static OWLClass asset_valuation ;
			public static OWLClass context;
			public static OWLClass safeguards;
			public static OWLClass security_events;
			public static OWLClass incident;
			public static OWLClass risk_management;
			public static OWLClass risk_assessment;
			public static OWLClass threat;
			public static OWLClass risk_severity;
			public static OWLClass risk_scope;
			public static OWLClass risk;
			public static OWLClass risk_impact;
			public static OWLClass risk_owner;
			public static OWLClass risk_probability;
			String baseO;
			
			
			

			
			
		public DRM (OWLDataFactory dataFactory, OWLOntologyManager man, String base) {
			this.dataFactory= dataFactory;
			this.man = man;
			this.base = "http://www.semanticweb.org/upm/ontologies/2019/11/cyberthreat_DRM";
			
			 //http://.org/2020/...#
			PrefixManager pm = new DefaultPrefixManager(this.base + "#");
			
			asset = dataFactory.getOWLClass(":Asset", pm);
			asset_valuation = dataFactory.getOWLClass(":Asset_Valuation", pm);
			context = dataFactory.getOWLClass(":Context", pm);
			safeguards = dataFactory.getOWLClass(":Safeguards", pm);
			security_events = dataFactory.getOWLClass(":Security_Events", pm);
			incident = dataFactory.getOWLClass(":Incident", pm);
			risk_management = dataFactory.getOWLClass(":Risk_Management", pm);
			risk_assessment = dataFactory.getOWLClass(":Risk_Assessment", pm);
			threat = dataFactory.getOWLClass(":Threat", pm);
			risk_severity = dataFactory.getOWLClass(":Risk_Severity", pm);
			risk_scope = dataFactory.getOWLClass(":Risk_Scope", pm);
			risk = dataFactory.getOWLClass(":Risk", pm);
			risk_impact = dataFactory.getOWLClass(":Risk_Impact", pm);
			risk_owner = dataFactory.getOWLClass(":Risk_Owner", pm);
			risk_probability = dataFactory.getOWLClass(":Risk_Probability", pm);

			this.baseO=base;
		}



		public static OWLClass getAsset() {
			return asset;
		}



		public static void setAsset(OWLClass asset) {
			DRM.asset = asset;
		}



		public static OWLClass getAsset_valuation() {
			return asset_valuation;
		}



		public static void setAsset_valuation(OWLClass asset_valuation) {
			DRM.asset_valuation = asset_valuation;
		}



		public static OWLClass getContext() {
			return context;
		}



		public static void setContext(OWLClass context) {
			DRM.context = context;
		}



		public static OWLClass getSafeguards() {
			return safeguards;
		}



		public static void setSafeguards(OWLClass safeguards) {
			DRM.safeguards = safeguards;
		}



		public static OWLClass getSecurity_events() {
			return security_events;
		}



		public static void setSecurity_events(OWLClass security_events) {
			DRM.security_events = security_events;
		}



		public static OWLClass getIncident() {
			return incident;
		}



		public static void setIncident(OWLClass incident) {
			DRM.incident = incident;
		}



		public static OWLClass getRisk_management() {
			return risk_management;
		}



		public static void setRisk_management(OWLClass risk_management) {
			DRM.risk_management = risk_management;
		}



		public static OWLClass getRisk_assessment() {
			return risk_assessment;
		}



		public static void setRisk_assessment(OWLClass risk_assessment) {
			DRM.risk_assessment = risk_assessment;
		}



		public static OWLClass getThreat() {
			return threat;
		}



		public static void setThreat(OWLClass threat) {
			DRM.threat = threat;
		}



		public static OWLClass getRisk_severity() {
			return risk_severity;
		}



		public static void setRisk_severity(OWLClass risk_severity) {
			DRM.risk_severity = risk_severity;
		}



		public static OWLClass getRisk_scope() {
			return risk_scope;
		}



		public static void setRisk_scope(OWLClass risk_scope) {
			DRM.risk_scope = risk_scope;
		}



		public static OWLClass getRisk() {
			return risk;
		}



		public static void setRisk(OWLClass risk) {
			DRM.risk = risk;
		}



		public static OWLClass getRisk_impact() {
			return risk_impact;
		}



		public static void setRisk_impact(OWLClass risk_impact) {
			DRM.risk_impact = risk_impact;
		}



		public static OWLClass getRisk_owner() {
			return risk_owner;
		}



		public static void setRisk_owner(OWLClass risk_owner) {
			DRM.risk_owner = risk_owner;
		}



		public static OWLClass getRisk_probability() {
			return risk_probability;
		}



		public static void setRisk_probability(OWLClass risk_probability) {
			DRM.risk_probability = risk_probability;
		}
		
		
		public void  createDRMInstances (OWLOntologyManager man, OWLOntology o, OWLDataFactory dataFactory, String drmType, String individualName) {
		       
			OWLIndividual drm_instance = dataFactory.getOWLNamedIndividual(IRI.create(this.baseO +"#"+individualName));

			if(drmType.equals("Asset")) {
				OWLClassAssertionAxiom axioma0 = dataFactory.getOWLClassAssertionAxiom(asset, drm_instance);
				man.addAxiom(o, axioma0);
				System.out.println(axioma0);

			}
			else if(drmType.equals("Asset_Valuation")) {
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(asset_valuation, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Context")) {
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(context, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Safeguards")) {
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(safeguards, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Security_Events")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(security_events, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Incident")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(incident, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Risk_Management")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(risk_management, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Risk_Assessment")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(risk_assessment, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Threat")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(threat, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Risk_Severity")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(risk_severity, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Risk_Scope")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(risk_scope, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Risk")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(risk, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Risk_Impact")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(risk_impact, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Risk_Owner")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(risk_owner, drm_instance);
				man.addAxiom(o, axioma);
			}
			else if(drmType.equals("Risk_Probability")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(risk_probability, drm_instance);
				man.addAxiom(o, axioma);
			}
			else {
				System.out.println("The DRM type selected does not exist");
			}
			
	    	System.out.println("The individual "+drm_instance+ " was created");	
		}
}
