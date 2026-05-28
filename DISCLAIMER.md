# Disclaimer

OT Sentinel is an **independent, community-driven open-source project**. It is NOT affiliated with, endorsed by, or sponsored by:

- Any Industrial Control System (ICS) or Operational Technology (OT) vendor
- Any government agency or regulatory body
- Any security product vendor (including Wazuh Inc.)
- Any employer of the project maintainers

---

## Important Caveats

### 1. Experimental Status
All rules are marked `experimental` until they have been tested against a real OpenPLC + GNS3 digital twin lab. Rules marked `tested: yes` have been validated in a controlled lab environment but may still produce false positives or false negatives in your specific environment.

### 2. Not a Replacement for Professional OT Security
OT Sentinel rules are a **supplement** to, not a replacement for:
- Professional OT/ICS security assessments
- Network segmentation and air-gapping controls
- Vendor-provided security monitoring solutions
- Certified OT security personnel

### 3. Deployment Risks
- **False positives**: Detection rules may trigger on legitimate OT traffic. Always test in a non-production environment first.
- **False negatives**: No set of rules can detect all attacks. OT Sentinel is a starting point, not a comprehensive solution.
- **Performance impact**: Aggressive rule matching on high-throughput OT networks may impact SIEM performance. Tune thresholds for your environment.

### 4. Protocol-Specific Considerations
- **Modbus** has no built-in authentication. Detection relies on network-level allowlisting, which may be bypassed by IP spoofing.
- **DNP3 Secure Authentication v5** is rarely deployed in practice. Rules assume unauthenticated DNP3 traffic.
- **MQTT** QoS levels and topic structures vary widely between deployments. Customize topic allowlists for your environment.
- **IEC 104** ASDU structures are implementation-specific. Test field extraction against your specific RTU/PLC configuration.

### 5. No Warranty
THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Legal Notice

The MITRE ATT&CK for ICS framework is © The MITRE Corporation. OT Sentinel's use of ATT&CK technique IDs is for informational and mapping purposes only and does not imply endorsement by MITRE.

All protocol specifications referenced in OT Sentinel documentation are the intellectual property of their respective standards bodies (Modbus Organization, DNP Users Group, IEC, OASIS, OPC Foundation).

---

## Contact

For questions about the disclaimer: open an issue on the GitHub repository.

---

*Last updated: 2026-05-27*
