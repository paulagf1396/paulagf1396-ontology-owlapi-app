package owl.upm.cyberthreat.owlapi;

import java.util.HashMap;
import java.util.Map;

import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.rio.RioBinaryRdfStorerFactory;
import org.semanticweb.owlapi.util.DefaultPrefixManager;

public class STIX {

		//Different Classes from DRM in the Ontology
		private OWLDataFactory dataFactory;
		private OWLOntologyManager man;
		public String base;
		public static OWLClass attack_pattern;
		public static OWLClass bundle ;
		public static OWLClass campaign;
		public static OWLClass course_of_action;
		public static OWLClass cyberobservable;
		public static OWLClass dictionary;
		public static OWLClass identity;
		public static OWLClass incident;
		public static OWLClass indicator;
		public static OWLClass infraestructure;
		public static OWLClass intrusion_set;
		public static OWLClass kill_chain_phase;
		public static OWLClass malware;
		public static OWLClass malware_analysis;
		public static OWLClass marking_definition;
		public static OWLClass observed_data;
		public static OWLClass report;
		public static OWLClass sighting;
		public static OWLClass threat_actor;
		public static OWLClass tool;
		public static OWLClass vulnerability;
		public static OWLClass grouping;
		public static OWLClass location;
		public static OWLClass note;
		public static OWLClass opinion;
		public static OWLClass relationship;
		
		public static HashMap<String, OWLClass> ciberobservable_types = new HashMap<String, OWLClass>();
		String [] ciberobservables_names = {"Artifact", "Autonomous_System", "Directory", "Domain_Name", "Email_Address", "Email_Message", "File", "IPV4Addr" , "IPV6Addr", "Mutex", "MAC-Addr", "Network_Traffic", "Process", "Software", "URL", "User_Account", "Windows_Registry_Key", "X509_Certificate"};

		String baseO;

	
	
		public STIX (OWLDataFactory dataFactory, OWLOntologyManager man, String base) {
			this.dataFactory= dataFactory;
			this.man = man;
			this.base = "http://www.semanticweb.org/upm/ontologies/2019/11/cyberthreat_STIX";
			
			 //http://.org/2020/...#
			PrefixManager pm = new DefaultPrefixManager(this.base + "#");
			
			attack_pattern = dataFactory.getOWLClass(":Attack_Pattern", pm);
			bundle = dataFactory.getOWLClass(":Bundle", pm);
			campaign = dataFactory.getOWLClass(":Campaign", pm);
			course_of_action = dataFactory.getOWLClass(":Course_of_Action", pm);
			cyberobservable = dataFactory.getOWLClass(":Cyber_Observables", pm);
			dictionary = dataFactory.getOWLClass(":Dictionary", pm);
			identity = dataFactory.getOWLClass(":Identity", pm);
			incident = dataFactory.getOWLClass(":Incident", pm);
			indicator = dataFactory.getOWLClass(":Indicator", pm);
			infraestructure = dataFactory.getOWLClass(":Infraestructure", pm);
			intrusion_set = dataFactory.getOWLClass(":Intrusion_Set", pm);
			kill_chain_phase = dataFactory.getOWLClass(":Kill_Chain_Phase", pm);
			malware = dataFactory.getOWLClass(":Malware", pm);
			malware_analysis = dataFactory.getOWLClass(":Malware_Analysis", pm);
			marking_definition = dataFactory.getOWLClass(":Marking_Definition", pm);
			observed_data = dataFactory.getOWLClass(":Observed_Data", pm);
			report = dataFactory.getOWLClass(":Report", pm);
			sighting = dataFactory.getOWLClass(":Sighting", pm);
			threat_actor = dataFactory.getOWLClass(":Threat_Actor", pm);
			tool = dataFactory.getOWLClass(":Tool", pm);
			vulnerability = dataFactory.getOWLClass(":Vulnerability", pm);
			grouping = dataFactory.getOWLClass(":Grouping", pm);
			location = dataFactory.getOWLClass(":Location", pm);
			note = dataFactory.getOWLClass(":Note", pm);
			opinion = dataFactory.getOWLClass(":Opinion", pm);
			relationship = dataFactory.getOWLClass(":Relationship", pm);

			this.baseO= base;
			
			loadCiberObservables(ciberobservables_names);
			
			
		}
		
		private void loadCiberObservables(String[] names) {
			PrefixManager pm = new DefaultPrefixManager(this.base + "#");
			for (int i = 0; i<names.length-1; i++ ) {
				String name = names[i];
				OWLClass ontoClass = dataFactory.getOWLClass(":"+name, pm);
				ciberobservable_types.put(name, ontoClass);
			}
		}
		
		
		public static OWLClass getAttack_pattern() {
			return attack_pattern;
		}


		public static void setAttack_pattern(OWLClass attack_pattern) {
			STIX.attack_pattern = attack_pattern;
		}


		public static OWLClass getBundle() {
			return bundle;
		}


		public static void setBundle(OWLClass bundle) {
			STIX.bundle = bundle;
		}


		public static OWLClass getCampaign() {
			return campaign;
		}


		public static void setCampaign(OWLClass campaign) {
			STIX.campaign = campaign;
		}


		public static OWLClass getCourse_of_action() {
			return course_of_action;
		}


		public static void setCourse_of_action(OWLClass course_of_action) {
			STIX.course_of_action = course_of_action;
		}


		public static OWLClass getCyberobservable() {
			return cyberobservable;
		}

		public OWLClass getCyberobservableType(String name) {
			
			return ciberobservable_types.get(name);
		}

		public static void setCyberobservable(OWLClass cyberobservable) {
			STIX.cyberobservable = cyberobservable;
		}


		public static OWLClass getDictionary() {
			return dictionary;
		}


		public static void setDictionary(OWLClass dictionary) {
			STIX.dictionary = dictionary;
		}


		public static OWLClass getIdentity() {
			return identity;
		}


		public static void setIdentity(OWLClass identity) {
			STIX.identity = identity;
		}


		public static OWLClass getIncident() {
			return incident;
		}


		public static void setIncident(OWLClass incident) {
			STIX.incident = incident;
		}


		public static OWLClass getIndicator() {
			return indicator;
		}


		public static void setIndicator(OWLClass indicator) {
			STIX.indicator = indicator;
		}


		public static OWLClass getInfraestructure() {
			return infraestructure;
		}


		public static void setInfraestructure(OWLClass infraestructure) {
			STIX.infraestructure = infraestructure;
		}


		public static OWLClass getIntrusion_set() {
			return intrusion_set;
		}


		public static void setIntrusion_set(OWLClass intrusion_set) {
			STIX.intrusion_set = intrusion_set;
		}


		public static OWLClass getKill_chain_phase() {
			return kill_chain_phase;
		}


		public static void setKill_chain_phase(OWLClass kill_chain_phase) {
			STIX.kill_chain_phase = kill_chain_phase;
		}


		public static OWLClass getMalware() {
			return malware;
		}


		public static void setMalware(OWLClass malware) {
			STIX.malware = malware;
		}


		public static OWLClass getMalware_analysis() {
			return malware_analysis;
		}


		public static void setMalware_analysis(OWLClass malware_analysis) {
			STIX.malware_analysis = malware_analysis;
		}


		public static OWLClass getMarking_definition() {
			return marking_definition;
		}


		public static void setMarking_definition(OWLClass marking_definition) {
			STIX.marking_definition = marking_definition;
		}


		public static OWLClass getObserved_data() {
			return observed_data;
		}


		public static void setObserved_data(OWLClass observed_data) {
			STIX.observed_data = observed_data;
		}


		public static OWLClass getReport() {
			return report;
		}


		public static void setReport(OWLClass report) {
			STIX.report = report;
		}


		public static OWLClass getSighting() {
			return sighting;
		}


		public static void setSighting(OWLClass sighting) {
			STIX.sighting = sighting;
		}


		public static OWLClass getThreat_actor() {
			return threat_actor;
		}


		public static void setThreat_actor(OWLClass threat_actor) {
			STIX.threat_actor = threat_actor;
		}


		public static OWLClass getTool() {
			return tool;
		}


		public static void setTool(OWLClass tool) {
			STIX.tool = tool;
		}


		public static OWLClass getVulnerability() {
			return vulnerability;
		}


		public static void setVulnerability(OWLClass vulnerability) {
			STIX.vulnerability = vulnerability;
		}


		public static OWLClass getGrouping() {
			return grouping;
		}


		public static void setGrouping(OWLClass grouping) {
			STIX.grouping = grouping;
		}


		public static OWLClass getLocation() {
			return location;
		}


		public static void setLocation(OWLClass location) {
			STIX.location = location;
		}


		public static OWLClass getNote() {
			return note;
		}


		public static void setNote(OWLClass note) {
			STIX.note = note;
		}


		public static OWLClass getOpinion() {
			return opinion;
		}


		public static void setOpinion(OWLClass opinion) {
			STIX.opinion = opinion;
		}


		public static OWLClass getRelationship() {
			return relationship;
		}


		public static void setRelationship(OWLClass relationship) {
			STIX.relationship = relationship;
		}
		public void  createSTIXInstances (OWLOntologyManager man, OWLOntology o, OWLDataFactory dataFactory, String stixType, String individualName) {
		       
			OWLIndividual stix_instance = dataFactory.getOWLNamedIndividual(IRI.create(this.baseO +"#"+individualName));

			if(stixType.equals("Attack_Pattern")) {
				OWLClassAssertionAxiom axioma0 = dataFactory.getOWLClassAssertionAxiom(attack_pattern, stix_instance);
				man.addAxiom(o, axioma0);
				System.out.println(axioma0);
			}
			else if(stixType.equals("Bundle")) {
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(bundle, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Campaign")) {
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(campaign, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Course_of_Action")) {
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(course_of_action, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Cyber_Observables")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(cyberobservable, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Dictionary")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(dictionary, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Identity")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(identity, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Incident")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(incident, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Indicator")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(indicator, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Infraestructure")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(infraestructure, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Intrusion_Set")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(intrusion_set, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Kill_Chain_Phase")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(kill_chain_phase, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Malware")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(malware, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Malware_Analysis")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(malware_analysis, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Marking_Definition")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(marking_definition, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Observed_Data")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(observed_data, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Report")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(report, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Sighting")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(sighting, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Threat_Actor")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(threat_actor, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Tool")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(tool, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Vulnerability")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(vulnerability, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Grouping")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(grouping, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Location")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(location, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Note")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(note, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Opinion")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(opinion, stix_instance);
				man.addAxiom(o, axioma);
			}
			else if(stixType.equals("Relationship")){
				OWLClassAssertionAxiom axioma = dataFactory.getOWLClassAssertionAxiom(relationship, stix_instance);
				man.addAxiom(o, axioma);
			}
			else {
				System.out.println("The STIX type selected does not exist");
			}
			
	    	System.out.println("The individual "+stix_instance+ " was created");	
		}
}
