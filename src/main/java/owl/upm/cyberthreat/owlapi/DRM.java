package owl.upm.cyberthreat.owlapi;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.semanticweb.owlapi.model.AxiomType;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
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
import org.semanticweb.owlapi.util.DefaultPrefixManager;
import org.semanticweb.owlapi.vocab.OWL2Datatype;

public class DRM {

		//Different Classes from DRM in the Ontology
		private OWLDataFactory dataFactory;
		private OWLOntologyManager man;
		public static String base;
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
		public static String baseO;
		
		public static HashMap<String, OWLClass> asset_types = new HashMap<String, OWLClass>();
		public static String [] asset_names = {"AcquiredSW", "Archive_File_Extension", "Building", "BusinessRecovery", "CellCommunications", "ClassifiedData", "Computer", "Contractors", "Data", "DevelopedSW", "ExternalUsers", "File", "Floor", "Hardware", "InternalUsers", "Internet", 
				"IoT", "ISDN", "LAN", "MainBackboneHW", "MobileDevices", "Modem", "NetworkDevice", "Networks", "NTFS_File_Extension", "PDF_File_Extension", "PersonalComputer", "PersonalDataProtection", "Process", "Processes", "PSTN", "Raster_Image_File_Extension", "RealEstate",
				"RelatedProcesses", "Room", "Router", "SatelliteCommunications", "SelfProvided", "Server", "ServiceDelivery", "Software", "Switch", "ThirdPartyProvided", "Users", "VirtualMachines", "VLAN", "VPN", "Windows-PE-Optional-Header-Type", "Windows-PE-Section-Type", 
				"Windows_PE_Binary_File_Extension", "Windows_Proccess_Extension", "Windows_Service_Extension", "WLAN", "xDSL"};
		
		
		public static HashMap<String, OWLClass> threat_types = new HashMap<String, OWLClass>();
		public static String [] threat_names = {"Accidents", "BadReputationThreat", "ConfigurationError", "CorporateBrandImageDamages", "DataProtectionRisks", "DelayedDelivery", "DeliberatedConfigFilesTampering", "DeliberatedHWTampering", 
				"DeliberatedInformationDestruction", "DeliberatedInformationLeak", "DeliberatedInformationTampering", "DeliberatedMaliciousSWDistribution", "DeliberatedRegistersTampering", "DeliberatedSWTampering", "DeliberatedUnauthorizedAccess", "DenialOfService",
				"DeviceLost", "DeviceTheft",  "Fire", "HWMaintenanceError", "HumanResourcesNotAvailable", "IdentityThief", "InsiderThreats", "MonitoringError", "NaturalDisasters", "NetworkOutage",
				"NonIntentionalAdminError", "NonIntentionalInformationDestruction", "NonIntentionalInformationLeak", "NonIntentionalInformationTampering", "NonIntentionalMaliciousSWDistribution", "NonIntentionalUserError", "OtherLegalObligationRisks", "PartnershipsIssues",
					"PhysicalFault", "PowerOutage", "PrivilegeEscalation", "SWMaintenanceError", "SWVulnerabilities", "SocialEngineering", "StakeholdersIssues", "StakeholdersSatisfaction", "StrategicPlanOnRisk",
					"TechnicalComplexity", "Terrorism", "Untrustworthy", "UsersComplaints" ,"UnexpectedUsage"};
			

		public static HashMap<String, OWLClass> risk_types = new HashMap<String, OWLClass>();
		public static String [] risk_names = 	{"AccidentRisk", "BadReputationRisk", "ConfigurationErrorRisk", "CorporateBrandImageDamageRisk", "DataProtectionComplianceRisk", "DelayedDeliveryRisk", "DeliberatedConfigFilesTamperingRisk", "DeliberatedHWTamperingRisk",
				"DeliberatedInformationDestructionRisk", "DeliberatedInformationLeakRisk", "DeliberatedInformationTamperingRisk", "DeliberatedMaliciousSWDistributionRisk", "DeliberatedRegistersTamperingRisk", "DeliberatedSWTamperingRisk", "DeliberatedUnauthorizedAccessRisk", "DenialOfServiceRisk",
				"DeviceLostRisk", "DeviceTheftRisk", "FireRisk", "HWMaintenanceErrorRisk", "HumanResourcesNotAvailableRisk", "IdentityThiefRisk", "LogicalFailureRisk", "MonitoringErrorRisk", "NaturalDisasterRisk", "NetworkOutageRisk", "NonIntentionalAdminErrorRisk",
				"NonIntentionalInformationDestructionRisk", "NonIntentionalInformationLeakRisk", "NonIntentionalInformationTamperingRisk", "NonIntentionalMaliciousSWDistributionRisk", "NonIntentionalUserErrorRisk", "OtherLegalComplianceRisk", "OtherRisk",
				"PartnershipRisk", "PhysicalFailureRisk", "PowerOutageRisk", "PressNegativeImpactRisk", "SWMaintenanceErrorRisk", "SWVulnerabilitiesRisk", "SocialEngineeringRisk", "StakeholdersRisk", "StakeholdersSatisfactionRisk", "StrategicObjectiveRisk",
				"TechnicalComplexityDerivedRisk", "TerrorismAttackRisk", "UntrustworthyRisk", "UsersComplaintsRisk", "FloodingRisk","EconomicLoss"};
			
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
			
			loadThreatTypes(threat_names);
			loadRiskTypes(risk_names);
			loadAssetTypes(asset_names);
			
		}

		private void loadThreatTypes(String[] names) {
			PrefixManager pm = new DefaultPrefixManager(this.base + "#");
			for (int i = 0; i<names.length-1; i++ ) {
				String name = names[i];
				OWLClass ontoClass = dataFactory.getOWLClass(":"+name, pm);
				threat_types.put(name, ontoClass);
			}
		}
		
		private void loadRiskTypes(String[] names) {
			PrefixManager pm = new DefaultPrefixManager(this.base + "#");
			for (int i = 0; i<names.length-1; i++ ) {
				String name = names[i];
				OWLClass ontoClass = dataFactory.getOWLClass(":"+name, pm);
				risk_types.put(name, ontoClass);
			}
		}
		
		private void loadAssetTypes(String[] names) {
			PrefixManager pm = new DefaultPrefixManager(this.base + "#");
			for (int i = 0; i<names.length-1; i++ ) {
				String name = names[i];
				OWLClass ontoClass = dataFactory.getOWLClass(":"+name, pm);
				asset_types.put(name, ontoClass);
			}
		}
		


		public static OWLClass getAsset() {
			return asset;
		}



		public static void setAsset(OWLClass asset) {
			DRM.asset = asset;
		}

		public OWLClass getAssetByType(String name) {
			
			return asset_types.get(name);
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

		public static OWLClass getThreatByType(String name) {
			
			return threat_types.get(name);
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

		public static OWLClass getRiskByType(String name) {
			
			return risk_types.get(name);
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
		
		public void  createAssets (OWLOntologyManager man, OWLOntology o, OWLDataFactory dataFactory, String drmType,  String element) {
			if(element.length()>0) {
				element = element.replace("\"", "").replace("[", "_").replace("]", "");
				String[] activosDentro = element.split(";;_");
				for(int i = 1; i<activosDentro.length; i++){
					String activo = activosDentro[i]; 
					System.out.println(activo);

					//split1[0] es assetname y split1[1]dependencias
					String[] split1 = activo.split(";;;");
					
					//split2[0] tipo y split2[1] assetname
					String split2 = split1[0];
					
					//Saco  TYPE
					int ind = activosDentro[0].indexOf(" ");
					//String code = split2[0].substring(0, ind+1);
					String type = activosDentro[0].substring(ind+1);
					System.out.println(type);
					
					
					//Saco code + assetName
					int space = split1[0].indexOf(" ");
					String code = split2.substring(0, space);
					System.out.println(code);
					String assetName = split1[0].replace(" ", "");
					System.out.println(assetName);
					if(split1.length==1) {
						assetName= assetName.replace(";", "");
					}
					
					//Saco dependencias
					List dependencias = new ArrayList<String>();
					if(split1.length>1) {
						for(int j = 1; j<split1.length; j++) {
							
							//Divide el numero y el valor de la dependencia
							String[] split3= split1[j].split(";");
							String valor = split3[1].replace(" ", "");
							
							dependencias.add(valor);
							
						}
					}
					
					
					
					PrefixManager pm = new DefaultPrefixManager(base + "#");
					PrefixManager pmO = new DefaultPrefixManager(baseO + "#");
					
					//Creo la instancia del activo
					OWLIndividual asset_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+assetName));
					System.out.println(asset_instance);
					OWLClass aType = getAssetByType(type);
					OWLClassAssertionAxiom axioma0 = dataFactory.getOWLClassAssertionAxiom(aType, asset_instance);
					man.addAxiom(o, axioma0);
					System.out.println(axioma0);
					
					
					//meto ID
					OWLDataProperty dproperty_Code = dataFactory.getOWLDataProperty(":code", pmO);	
					createDataProperty(o, man, dataFactory, base, asset_instance, dproperty_Code, code);
					
					//meto Type
					OWLDataProperty dproperty_Type = dataFactory.getOWLDataProperty(":type", pmO);	
					createDataProperty(o, man, dataFactory, base, asset_instance, dproperty_Type, type);
					
					//meto dependsOn
						
				}
				

			}
			
		
			
			
		}
		
		public void  createDependencias (OWLOntologyManager man, OWLOntology o, OWLDataFactory dataFactory, String drmType,  String element) throws OWLOntologyStorageException {
			if(element.length()>0) {
				element = element.replace("\"", "").replace("[", "").replace("]", "");   
				//split1[0] es tipo+assetname y split1[1]dependencias
				String[] split1 = element.split(";;;");
				
				//split2[0] tipo y split2[1] assetname
				String[] split2 = split1[0].split(";;");
				
				//Saco assetName
				String assetName = split2[1].replace(" ", "");
				if(split1.length==1) {
					assetName= assetName.replace(";", "");
				}
				
				//Saco dependencias
				List dependencias = new ArrayList<String>();
				if(split1.length>1) {
					for(int j = 1; j<split1.length; j++) {
						
						//Divide el numero y el valor de la dependencia
						String[] split3= split1[j].split(";");
						String valor = split3[1].replace(" ", "");
						
						dependencias.add(valor);
					}
				}
				
				
				
				PrefixManager pm = new DefaultPrefixManager(base + "#");
				PrefixManager pmO = new DefaultPrefixManager(baseO + "#");
				
				//meto dependsOn
				OWLIndividual asset_instance = dataFactory.getOWLNamedIndividual(":"+assetName, pm);
				for (int k = 0; k<dependencias.size(); k++) {
					OWLIndividual depenIndividual = dataFactory.getOWLNamedIndividual(":"+dependencias.get(k), pm);
					createObjectProperty(o, man, dataFactory, base, asset_instance, depenIndividual, "dependsOn");
				}

			}
			
		
			
			
		}
		
		public void createAssetValuation(OWLOntologyManager man, OWLOntology o, OWLDataFactory dataFactory, List<String[]> valoraciones) throws OWLOntologyStorageException {
			PrefixManager pm = new DefaultPrefixManager(base + "#");
			PrefixManager pmO = new DefaultPrefixManager(baseO + "#");
			
			System.out.println("Estas creandote el asset valuation de tus activos");
			if(valoraciones.isEmpty()) {
				System.out.println("No hay valoraciones");
			}
			else {
				
				String code = "";
				for(String[] v: valoraciones) {
					if(!v[0].equals(code)) {
						
						code = v[0];
						OWLIndividual av_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#AV"+code));
						OWLClassAssertionAxiom axioma1 = dataFactory.getOWLClassAssertionAxiom(getAsset_valuation(), av_instance);
						man.addAxiom(o, axioma1);
						
						OWLIndividual riskScope_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#RS"+code));
						OWLClassAssertionAxiom axioma2 = dataFactory.getOWLClassAssertionAxiom(risk_scope, riskScope_instance);
						man.addAxiom(o, axioma2);
						
						createObjectProperty(o, man, dataFactory, baseO, av_instance, riskScope_instance, "evaluates");

						OWLIndividual asset_instance = searchAsset(o, code);
						createObjectProperty(o, man, dataFactory, base, riskScope_instance, asset_instance, "dependsOn");
					}
					
					String dcode = v[1];
					String value = v[2];
					OWLIndividual av = dataFactory.getOWLNamedIndividual(":AV"+code, pm);
					
					if(dcode.equals("D")) {
						OWLDataProperty dproperty_Dcode = dataFactory.getOWLDataProperty(":availability", pmO);	
						createDataProperty(o, man, dataFactory, base, av, dproperty_Dcode, value);
					}else if(dcode.equals("I")) {
						OWLDataProperty dproperty_Dcode = dataFactory.getOWLDataProperty(":integrity", pmO);	
						createDataProperty(o, man, dataFactory, base, av, dproperty_Dcode, value);
					}else if(dcode.equals("C")) {
						OWLDataProperty dproperty_Dcode = dataFactory.getOWLDataProperty(":confidentiality", pmO);	
						createDataProperty(o, man, dataFactory, base, av, dproperty_Dcode, value);
					}else if(dcode.equals("A")) {
						OWLDataProperty dproperty_Dcode = dataFactory.getOWLDataProperty(":authenticity", pmO);	
						createDataProperty(o, man, dataFactory, base, av, dproperty_Dcode, value);
					}else if(dcode.equals("T")) {
						OWLDataProperty dproperty_Dcode = dataFactory.getOWLDataProperty(":accounting", pmO);	
						createDataProperty(o, man, dataFactory, base, av, dproperty_Dcode, value);
					}	
					
				}
 

			}
		}
		
		private OWLIndividual searchAsset(OWLOntology o, String code) {
			PrefixManager pmDRM = new DefaultPrefixManager(base + "#");
			PrefixManager pm = new DefaultPrefixManager(baseO + "#");
			
			OWLDataProperty pcode = dataFactory.getOWLDataProperty(":code", pm);
			OWLIndividual i = null ;
			Set<OWLNamedIndividual> instances = o.getIndividualsInSignature();
			for(OWLNamedIndividual ins: instances) {
				String codeValue = obtainDataPropertyValue(ins, pcode, o);
				if(codeValue != null && codeValue.equals(code) ) {
					i = ins;
				}	
			}
			
			return i;
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
		
		public void  createDRMInstances (OWLOntologyManager man, OWLOntology o, OWLDataFactory dataFactory, String drmType,  String individualName) {
		   
			OWLIndividual drm_instance = dataFactory.getOWLNamedIndividual(IRI.create(this.baseO +"#"+individualName));

			if(drmType.equals("Context")) {
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
		
		
		public void createDataProperty(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLIndividual object, OWLDataProperty dproperty, String value) {
			
			// Convenience methods of OWLDataFactory for common data types:
			OWLDatatype integerDatatype = dataFactory.getIntegerOWLDatatype();
			OWLDatatype floatDatatype = dataFactory.getFloatOWLDatatype();
			OWLDatatype doubleDatatype = dataFactory.getDoubleOWLDatatype();
			
			
			
			if (dproperty!=null &&  object!=null && value!=null) {
				Set<OWLDataPropertyAssertionAxiom> properties = o.getDataPropertyAssertionAxioms(object);
				for (OWLDataPropertyAssertionAxiom ax : properties) {
					if (ax.getProperty().equals(dproperty) && ax.getSubject().equals(object)) {
						man.removeAxiom(o, ax);
					}	
				}
				
				//Si es un double/integer/float
				if(StringUtils.isNumeric(value) || StringUtils.contains(value, ".") || StringUtils.startsWith(value, "-")) {
					Set<OWLDataPropertyRangeAxiom> c = o.getAxioms(AxiomType.DATA_PROPERTY_RANGE);
					for(OWLDataPropertyRangeAxiom d : c) {
							if(d.getProperty().equals(dproperty)) {
								OWLDataRange r = d.getRange();
								if(r.equals(floatDatatype)) {
									float valuef = Float.parseFloat(value);
									System.out.println("FLOAT VALUE "+valuef);
									OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, object, valuef);
									man.addAxiom(o, dAxiom);
									return;
								}
								if(r.equals(integerDatatype)){
									int valuei = Integer.parseInt(value);
									OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, object, valuei);
									man.addAxiom(o, dAxiom);return;
									
								}
								if(r.equals(doubleDatatype)){
									double valued = Double.parseDouble(value);
									System.out.println("DOUBLE VALUE "+valued);
									OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, object, valued);
									man.addAxiom(o, dAxiom);return;
								}
								
									
							}
							
						}
					
					}
				
				//si es string
				OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, object, value);
				man.addAxiom(o, dAxiom);
			}else {
				System.out.println("Not properly data to create Data Property for asset instance");
			}
			
			
		}	

		//Crear Object Properties DRM
		public void createObjectProperty(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLIndividual object1, OWLIndividual object2, String property) throws OWLOntologyStorageException {
			PrefixManager pm = new DefaultPrefixManager(base + "#");
			
			OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(":"+property, pm);	
			if (oproperty!=null &&  object1!=null && object2!=null) {
				OWLObjectPropertyAssertionAxiom oAxiom = dataFactory.getOWLObjectPropertyAssertionAxiom(oproperty, object1, object2);
				man.addAxiom(o, oAxiom);
		
			}else {
				System.out.println("Not properly data to create Object Property for asset instance");
			}
					
		
		}
	
	
		

}
