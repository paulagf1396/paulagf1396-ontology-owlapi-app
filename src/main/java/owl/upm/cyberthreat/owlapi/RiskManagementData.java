package owl.upm.cyberthreat.owlapi;

import java.util.Set;

public class RiskManagementData {

	
	private float actualRisk;
	private String recommendationType;
	private String riesgoARecomendar;
	
	
	public RiskManagementData(float actualRisk, String recommendationType, String riesgoARecomendar) {
		
		this.actualRisk = actualRisk;
		this.recommendationType= recommendationType;
		this.riesgoARecomendar = riesgoARecomendar;
		
	}


	public String getRiesgoARecomendar() {
		return riesgoARecomendar;
	}


	public void setRiesgoARecomendar(String riesgoARecomendar) {
		this.riesgoARecomendar = riesgoARecomendar;
	}


	public float getActualRisk() {
		return actualRisk;
	}


	public void setActualRisk(float actualRisk) {
		this.actualRisk = actualRisk;
	}


	public String getRecommendationType() {
		return recommendationType;
	}


	public void setRecommendationType(String recommendationType) {
		this.recommendationType = recommendationType;
	}

		
		
	

}
