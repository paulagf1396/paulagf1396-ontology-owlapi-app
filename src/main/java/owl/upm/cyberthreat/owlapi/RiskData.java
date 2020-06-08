package owl.upm.cyberthreat.owlapi;

public class RiskData {

	private String riskName;
	private double threatNum;
	private float pRisk;
	private float rRisk;
	private float impact;
	private float probability;
	
	public RiskData(String riskName, double threatNum, float pRisk, float rRisk, float impact, float probability) {
		this.riskName = riskName;
		this.threatNum = threatNum;
		this.pRisk = pRisk;
		this.rRisk = rRisk;
		this.impact = impact;
		this.probability = probability;
		
	}

	public String getRiskName() {
		return riskName;
	}

	public void setRiskName(String riskName) {
		this.riskName = riskName;
	}

	public double getThreatNum() {
		return threatNum;
	}

	public void setThreatNum(double threatNum) {
		this.threatNum = threatNum;
	}

	public float getpRisk() {
		return pRisk;
	}

	public void setpRisk(float pRisk) {
		this.pRisk = pRisk;
	}

	public float getrRisk() {
		return rRisk;
	}

	public void setrRisk(float rRisk) {
		this.rRisk = rRisk;
	}
	
	public float getImpact() {
		return impact;
	}

	public void setImpact(float impact) {
		this.impact = impact;
	}
	
	public float getProbability() {
		return probability;
	}

	public void setProbability(float probability) {
		this.probability = probability;
	}
	
	
	
}
