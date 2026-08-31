poxdir ?= /opt/pox/

# Complete the makefile as you prefer!
topo:
	@echo "starting the topology! (i.e., running mininet)"
	sudo python ./topology/topology.py

app:
	@echo "starting the baseController!"
	# Copy your controller to the POX folder
	cp applications/controller/* $(poxdir)ext/
	# Copy nfv click functions to the pox controller folder
	cp applications/nfv/*.click $(poxdir)ext/
	# Run controller that setups normal switches and CLICK nodes
	sudo python /opt/pox/pox.py baseController

test: #clean #clean the network
	# get sudo permission
	@sudo -v
	@echo "starting test scenarios!"

	# copy controller and click modules to pox directory
	sudo cp applications/controller/* $(poxdir)ext/
	sudo cp applications/nfv/*.click $(poxdir)ext/
	# start POX controller in background and save logs to controller.log
	sudo python3 $(poxdir)pox.py baseController > controller.log 2>&1 &
	# wait for 10 seconds for controller to fully start and listen on 6633 port
	sleep 10
	# run the test scenarios
	-sudo python3 ./topology/topology_test.py 2>&1 | tee phase_1_report
	@stty sane

	# clean up after the test
	@$(MAKE) clean
	# remove old files
	-@rm -rf results/*.report results/*.pcap results/phase_1_report 2>/dev/null || true

	sleep 3
	@mkdir -p results
	-@mv phase_1_report results/ 2>/dev/null || true
	-@mv ids.report results/ 2>/dev/null || true
	-@mv lb1.report results/ 2>/dev/null || true
	-@mv napt.report results/ 2>/dev/null || true
	-@mv inspector_proof.pcap results/ 2>/dev/null || true
	# move files done

clean:
	@echo "project files removed from pox directory!"
	# Remove files from ext dir in pox
	-sudo rm -f $(poxdir)ext/baseController.py $(poxdir)ext/click_wrapper.py $(poxdir)ext/*.click
	# Kill click processes
	-sudo killall click 2>/dev/null || true

	# Kill controller
	@# use the regexp trick to not match grep itself. And ignore the error if no pox running
	-sudo pkill -f "pox.py" || true
	# Clean mininet
	sudo mn -c
	




