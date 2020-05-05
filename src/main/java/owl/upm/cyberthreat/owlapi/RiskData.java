package owl.upm.cyberthreat.owlapi;

public class RiskData {

	private String riskName;
	private double threatNum;
	private float pRisk;
	private float rRisk;
	
	public RiskData(String riskName, double threatNum, float pRisk, float rRisk) {
		this.riskName = riskName;
		this.threatNum = threatNum;
		this.pRisk = pRisk;
		this.rRisk = rRisk;
		
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
	
	
	
}
