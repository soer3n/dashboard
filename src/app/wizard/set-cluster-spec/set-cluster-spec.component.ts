import {Component, Input, OnDestroy, OnInit} from '@angular/core';
import {FormControl, FormGroup, Validators} from '@angular/forms';
import {Subscription} from 'rxjs';
import {debounceTime} from 'rxjs/operators';
import {ApiService, WizardService} from '../../core/services';
import {ClusterNameGenerator} from '../../core/util/name-generator.service';
import {ClusterEntity, MasterVersion} from '../../shared/entity/ClusterEntity';

@Component({
  selector: 'kubermatic-set-cluster-spec',
  templateUrl: 'set-cluster-spec.component.html',
  styleUrls: ['set-cluster-spec.component.scss'],
})

export class SetClusterSpecComponent implements OnInit, OnDestroy {
  @Input() cluster: ClusterEntity;
  clusterSpecForm: FormGroup;
  masterVersions: MasterVersion[] = [];
  defaultVersion: string;
  checkMachineNetworksTooltip = '';
  private subscriptions: Subscription[] = [];
  isOnDevServer = false;

  constructor(
      private nameGenerator: ClusterNameGenerator, private api: ApiService, private wizardService: WizardService) {}

  ngOnInit(): void {
    this.clusterSpecForm = new FormGroup({
      name: new FormControl(this.cluster.name, [Validators.required, Validators.minLength(5)]),
      version: new FormControl(this.cluster.spec.version),
    });

    this.subscriptions.push(this.clusterSpecForm.valueChanges.pipe(debounceTime(1000)).subscribe(() => {
      this.setClusterSpec();
    }));

    this.loadMasterVersions();

    // Enable OpenShift only on dev.kubermatic.io.
    this.isOnDevServer = window.location.host.includes('dev.kubermatic.io');
  }

  ngOnDestroy(): void {
    for (const sub of this.subscriptions) {
      if (sub) {
        sub.unsubscribe();
      }
    }
  }

  generateName(): void {
    this.clusterSpecForm.patchValue({name: this.nameGenerator.generateName()});
  }

  loadMasterVersions(): void {
    this.subscriptions.push(this.api.getMasterVersions().subscribe((versions) => {
      this.masterVersions = versions;

      if (this.isOnDevServer) {
        this.masterVersions.push({
          version: '3.9',
          allowedNodeVersions: ['1.11.5'],
        });

        this.masterVersions.push({
          version: '3.10',
          allowedNodeVersions: ['1.11.5'],
        });

        this.masterVersions.push({
          version: '3.11',
          allowedNodeVersions: ['1.11.5'],
        });
      }

      for (const i in versions) {
        if (versions[i].default) {
          this.defaultVersion = versions[i].version;
          this.clusterSpecForm.controls.version.setValue(versions[i].version);
        }
      }
    }));
  }

  setClusterSpec(): void {
    this.wizardService.changeClusterSpec({
      name: this.clusterSpecForm.controls.name.value,
      version: this.clusterSpecForm.controls.version.value,
      valid: this.clusterSpecForm.valid,
    });
  }
}
